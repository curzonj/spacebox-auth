'use strict';

var urlUtil = require("url"),
    http = require("http"),
    express = require("express"),
    moment = require("moment"),
    logger = require('morgan'),
    npm_debug = require('debug'),
    log = npm_debug('auth:info'),
    error = npm_debug('auth:error'),
    debug = npm_debug('auth:debug'),
    bodyParser = require('body-parser'),
    uuidGen = require('node-uuid'),
    cookieParser = require('cookie-parser'),
    C = require('spacebox-common'),
    db = require('spacebox-common-native').db,
    qhttp = require("q-io/http"),
    Q = require('q')

var common_native = require('spacebox-common-native')
common_native.db_select('auth')
var db = common_native.db

Q.longStackSupport = true

C.configure({
    AUTH_URL: process.env.AUTH_URL,
    credentials: process.env.INTERNAL_CREDS,
})

var app = express()
var port = process.env.PORT || 5000

app.use(logger('dev'))
C.http.cors_policy(app)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({
    extended: false
}))
app.use(cookieParser())

var dao = {
    tokens: {
        get: function(uuid) {
            return db.
                query("select * from tokens where id=$1", [ uuid ]).
                then(function(data) {
                    return data[0]
                })
        },
        insert: function(doc) {
            return db.
                query("insert into tokens (id, account_id, privileged, expires) values (uuid_generate_v4(), $1, $2, $3) returning *",
                      [ doc.account_id, doc.privileged, new Date(doc.expires) ])
        }
    },
    accounts: {
        get: function(uuid) {
            return db.
                query("select * from accounts where id=$1", [ uuid ]).
                then(function(data) {
                    return data[0]
                })
        },
        insert: function(doc) {
            var fullDoc = C.deepMerge(doc, {
                secret: uuidGen.v4(),
                privileged: false,
                expires: null,
                google_account: null,
            });

            return db.
                query("insert into accounts (id, secret, privileged, expires, google_account) values (uuid_generate_v4(), $1, $2, $3, $4) returning *",
                      [ fullDoc.secret, fullDoc.privileged, fullDoc.expires, fullDoc.google_account ])
        }
    }
}

function getBasicAuth(req) {
    var authorization = req.headers.authorization

    if (!authorization) return {}

    var parts = authorization.split(' ')

    if (parts.length !== 2) return {}

    var scheme = parts[0],
        credentials = new Buffer(parts[1], 'base64').toString(),
        index = credentials.indexOf(':')

    if ('Basic' != scheme || index < 0) return {}

    var user = credentials.slice(0, index),
        pass = credentials.slice(index + 1)

    return {
        user: user,
        password: pass
    }
}

function authorizeRequest(req, restricted) {
    var auth_header = req.get('Authorization')
    if (auth_header === undefined) {
        throw new Error("not authorized")
    }

    var parts = auth_header.split(' ')

    // TODO make a way for internal apis to authorize
    // as a specific account without having to get a
    // different bearer token for each one. Perhaps
    // auth will return a certain account if the authorized
    // token has metadata appended to the end of it
    // or is fernet encoded.
    if (parts[0] != "Bearer") {
        throw new Error("not authorized")
    }

    return authorizeToken(parts[1], restricted)
}

function authorizeToken(token, restricted) {
    var sudo_account,
        original_token = token

    if (token.indexOf('/') > 0) {
        var parts = token.split('/')
        console.log('sudo_token parts', parts)

        token = parts[0]
        sudo_account = parts[1]
    }

    return dao.tokens.get(token).then(function(authorization) {
        var now = new Date().getTime()

        if (authorization === undefined) {
            throw new Error("authorization missing: "+original_token)
        } else if (authorization.expires < now) {
            throw new Error("authorization expired: "+original_token)
        }

        if ((restricted === true || restricted == 'true') &&
            authorization.privileged !== true) {
            throw new Error("rejected for restricted endpoint: "+authorization.account)
        }

        // If you are privileged, you can pretend to be anybody you want
        if (sudo_account !== undefined) {
            if(authorization.privileged === true) {
                authorization.account_id = sudo_account
            } else {
                throw new Error("invalid authorization token")
            }
        }

        return {
            account: authorization.account_id,
            expires: authorization.expires, // this is so they can cache it
            privileged: (authorization.privileged === true),
            groups: []
        }
    })
}

function authenticateGoogleToken(token) {
    return qhttp.read({
        method: 'GET',
        url: 'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token='+encodeURIComponent(token)
    
    }).then(function(body) {
        try {
            return JSON.parse(body.toString())
        } catch(e) {
            throw new C.http.Error(401, 'invalid_token', { token: token, body: body })
        }
    }).then(function(body) {
        if (body.issued_to !== process.env.GOOGLE_CLIENT_ID ||
            body.audience !== process.env.GOOGLE_CLIENT_ID ||
            body.verified_email !== true) {

            throw new C.http.Error(401, 'invalid_token', body)
        }

        return db.query("select * from accounts where google_account=$1", [ body.email ]).
            then(function(data) {
                if (data.length === 0) {
                    return dao.accounts.insert({ google_account: body.email })
                } else {
                    return data
                }
            }).then(function(data) {
                return data[0]
            })
    })
}

// Creates a temporary account that expires with a password
// nobody knows and returns the account id and an authenticated
// token
app.post('/accounts/temporary', function(req, res) {
    var auth

    try {
        auth = authorizeRequest(req, false)
    } catch(e) {
        return res.status(401).send(e.toString())
    }

    if(req.param('ttl') === undefined) {
        return res.status(400).send("must specify a ttl")
    }

    var ttl = parseInt(req.param('ttl'))
    var expires = new Date().getTime() + (ttl * 1000)

    dao.accounts.insert({
        parent: auth.account,
        expires: moment(expires).toDate()
    }).then(function(data) {
        return dao.tokens.insert({
            account_id: data[0].id,
            privileged: false,
            expires: expires
        })
    }).then(function(data) {
        res.send({
            account: data[0].account_id,
            expires: expires,
            privileged: false,
            groups: [],
            token: data[0].id
        })
    }).fail(C.http.errHandler(req, res, console.log)).done()
})

app.get('/account', function(req, res) {
    C.http.authorize_req(req).then(function(auth) {
        return dao.accounts.get(auth.account)
    }).then(function(data) {
        res.send(data)
    }).fail(C.http.errHandler(req, res, error)).done()
})

app.get('/auth', function(req, res) {
    Q.fcall(function () {
            var basic_auth = getBasicAuth(req)

            if (basic_auth.user === undefined) {
                return res.status(401).send("requires basic auth")
            } else if (basic_auth.user === 'google') {
                return authenticateGoogleToken(basic_auth.password)
            } else {
                return dao.accounts.get(basic_auth.user).
                tap(function(account_data) {
                    if (account_data === undefined || account_data.secret != basic_auth.password) {
                        throw new C.http.Error(401, 'invalid_credentials')
                    }
                })
            }
    }).then(function(account_data) {
        var account = account_data.id
        var ttl = parseInt(req.param('ttl') || 300) // default 5min ttl
        var expires = new Date().getTime() + (ttl * 1000)

        return dao.tokens.insert({
            account_id: account,
            privileged: (account_data.privileged === true),
            expires: expires
        }).then(function(data) {
            res.send({
                account: account,
                expires: expires,
                token: data[0].id
            })
        })
    }).fail(C.http.errHandler(req, res, console.log)).done()
})

app.post('/token', function(req, res) {
    var token = req.param('token') || req.body.token

    if (token === undefined) {
        return res.status(400).send('token parameter is required')
    }

    console.log("validating token", token, 'with request', req.headers['x-request-id'])

    try {
        authorizeToken(token, req.param('restricted')).then(function(auth) {
            console.log(auth)
            res.send(auth)
        }).fail(C.http.errHandler(req, res, console.log)).done()
    } catch(e) {
        console.log(e)
        console.log(e.stack)

        res.status(401).send(e.toString())
    }
})

app.get('/endpoints', function(req, res) {
    res.send({
        "3dsim": process.env.SPODB_URL,
        auth: process.env.AUTH_URL,
        tech: process.env.TECHDB_URL,
    })
})

var server = http.createServer(app)
server.listen(port)
console.log("server ready")
