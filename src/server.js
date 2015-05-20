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
    jwt = require('jsonwebtoken'),
    C = require('spacebox-common'),
    db = require('spacebox-common-native').db,
    qhttp = require("q-io/http"),
    Q = require('q')

var common_native = require('spacebox-common-native')
common_native.db_select('auth')
var db = common_native.db

Q.longStackSupport = true

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
    var ttl = parseInt(process.env.TOKEN_TTL || 300) // default 5min ttl

    C.authorize_req(req).then(function(auth) {
        return dao.accounts.insert({
            parent: auth.account,
            expires: moment().add(ttl, 'seconds').toDate()
        })
    }).then(function(data) {
        res.send(jwt.sign({
            account: data.id,
            privileged: false,
        }, process.env.JWT_SIG_KEY, {
            expiresInSeconds: ttl
        }))
    }).fail(C.http.errHandler(req, res, console.log)).done()
})

app.get('/account', function(req, res) {
    C.authorize_req(req).then(function(auth) {
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
        res.send(jwt.sign({
            account: account_data.id,
            privileged: (account_data.privileged === true)
        }, process.env.JWT_SIG_KEY, {
            expiresInSeconds: parseInt(process.env.TOKEN_TTL || 300) // default 5min ttl
        }))
    }).fail(C.http.errHandler(req, res, console.log)).done()
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
