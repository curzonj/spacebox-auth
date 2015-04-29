'use strict';

var urlUtil = require("url");
var http = require("http");
var express = require("express");
var logger = require('morgan');
var bodyParser = require('body-parser');
var uuidGen = require('node-uuid');
var cookieParser = require('cookie-parser');
var Q = require('q');

var pgpLib = require('pg-promise');
var pgp = pgpLib(/*options*/);
var database_url = process.env.DATABASE_URL || process.env.AUTH_DATABASE_URL;
var db = pgp(database_url);

var app = express();
var port = process.env.PORT || 5000;

app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: false
}));
app.use(cookieParser());

var tokensDAO = {
    get: function(uuid) {
        return db.
            query("select * from tokens where id=$1", [ uuid ]).
            then(function(data) {
                return data[0];
            });
    },
    insert: function(uuid, doc) {
        return db.
            query("insert into tokens (id, account_id, privileged, expires) values ($1, $2, $3, $4)",
                  [ uuid, doc.account_id, doc.privileged, new Date(doc.expires) ]);
    }
};

var accountsDAO = {
    get: function(uuid) {
        return db.
            query("select * from accounts where id=$1", [ uuid ]).
            then(function(data) {
                return data[0];
            });
    },
    insert: function(uuid, doc) {
        return db.
            query("insert into accounts (id, secret, privileged, expires) values ($1, $2, $3, $4)",
                  [ uuid, doc.secret, doc.privileged, doc.expires ]);
    }
};

function getBasicAuth(req) {
    var authorization = req.headers.authorization;

    if (!authorization) return {};

    var parts = authorization.split(' ');

    if (parts.length !== 2) return {};

    var scheme = parts[0],
        credentials = new Buffer(parts[1], 'base64').toString(),
        index = credentials.indexOf(':');

    if ('Basic' != scheme || index < 0) return {};

    var user = credentials.slice(0, index),
        pass = credentials.slice(index + 1);

    return {
        user: user,
        password: pass
    };
}

function isAPIRequest(req) {
    var header = req.get('content-type');
    return (header !== undefined && header.split(';')[0] == "application/json");
}

function authorizeRequest(req, restricted) {
    var auth_header = req.get('Authorization');
    if (auth_header === undefined) {
        throw new Error("not authorized");
    }

    var parts = auth_header.split(' ');

    // TODO make a way for internal apis to authorize
    // as a specific account without having to get a
    // different bearer token for each one. Perhaps
    // auth will return a certain account if the authorized
    // token has metadata appended to the end of it
    // or is fernet encoded.
    if (parts[0] != "Bearer") {
        throw new Error("not authorized");
    }

    return authorizeToken(parts[1], restricted);
}

function authorizeToken(token, restricted) {
    var sudo_account,
        original_token = token;

    if (token.indexOf('/') > 0) {
        var parts = token.split('/');

        token = parts[0];
        sudo_account = parts[1];
    }

    return tokensDAO.get(token).then(function(authorization) {
        var now = new Date().getTime();

        if (authorization === undefined) {
            throw new Error("authorization missing: "+original_token);
        } else if (authorization.expires < now) {
            throw new Error("authorization expired: "+original_token);
        }

        if ((restricted === true || restricted == 'true') &&
            authorization.privileged !== true) {
            throw new Error("rejected for restricted endpoint: "+authorization.account);
        }

        // If you are privileged, you can pretend to be anybody you want
        if (sudo_account !== undefined) {
            if(authorization.privileged === true) {
                authorization.account = sudo_account;
            } else {
                throw new Error("invalid authorization token");
            }
        }

        return {
            account: authorization.account_id,
            expires: authorization.expires, // this is so they can cache it
            privileged: (authorization.privileged === true),
            groups: []
        };
    });
}

// Creates a temporary account that expires with a password
// nobody knows and returns the account id and an authenticated
// token
app.post('/accounts/temporary', function(req, res) {
    var auth;

    try {
        auth = authorizeRequest(req, true);
    } catch(e) {
        return res.status(401).send(e.toString());
    }

    var parent = req.param('parent');
    var parentAccount; //accounts[parent];
    var privileged = false;

    if (parentAccount === undefined) {
        // TODO we'll enable this later
        //return res.status(401).send("invalid parent account");
    } else {
        privileged = parentAccount.privileged;
    }

    if (!isAPIRequest(req)) {
        return res.status(400).send("json requests only");
    } else if(req.param('ttl') === undefined) {
        return res.status(400).send("must specify a ttl");
// NOTE we are not enforcing the parent account requirement yet
//    } else if(parent === undefined || accounts[parent] === undefined) {
//        return res.status(400).send("must specify a valid parent account");
    }

    var account = uuidGen.v1();
    var token = uuidGen.v4();
    var ttl = parseInt(req.param('ttl'));
    var expires = new Date().getTime() + (ttl * 1000);

    accountsDAO.insert(account, {
        secret: uuidGen.v4(), // This is not given out
        //parent: parent,
        expires: expires,
        privileged: privileged
    }).then(function() {
        return tokensDAO.insert(token, {
            account_id: account,
            privileged: privileged,
            expires: expires
        });
    }).then(function() {
        res.send({
            account: account,
            parent: parent,
            expires: expires,
            privileged: privileged,
            groups: [],
            token: token
        });
    }).catch(function(e) {
        console.log(e);
        console.log(e.stack);
        res.status(500).send(e.toString());
    }).done();
});



app.post('/accounts', function(req, res) {
    if (!isAPIRequest(req)) {
        return res.status(400).send("json requests only");
    }

    var account = uuidGen.v1();

    accountsDAO.insert(account, {
        secret: req.body.secret,
        privileged: (req.body.privileged === true)
    }).then(function() {
        res.send({ account: account });
    }).catch(function(e) {
        console.log(e);
        console.log(e.stack);
        res.status(500).send(e.toString());
    }).done();
});

app.get('/auth', function(req, res) {
    var account, secret;

    Q.fcall(function () {
        if (isAPIRequest(req)) {
            var basic_auth = getBasicAuth(req);
            if (basic_auth.user === undefined) return res.status(401).send("requires basic auth");

            account = basic_auth.user;
            secret = basic_auth.password;
        } else {
            secret = req.cookies.account_secret;
            account = req.cookies.account;

            if (account === undefined) {
                account = uuidGen.v1();
                secret = uuidGen.v4();

                return accountsDAO.insert(account, {
                    secret: secret
                });
            }
        }
    }).then(function() {
        return accountsDAO.get(account);
    }).then(function(account_data) {
        if (account_data === undefined || account_data.secret != secret) {
            return res.sendStatus(401);
        }

        var token = uuidGen.v4();
        var ttl = parseInt(req.param('ttl') || 300); // default 5min ttl
        var expires = new Date().getTime() + (ttl * 1000);

        return tokensDAO.insert(token, {
            account_id: account,
            privileged: (account_data.privileged === true),
            expires: expires
        }).then(function() {
            if (isAPIRequest(req)) {
                res.send({
                    account: account,
                    expires: expires,
                    token: token
                });
            } else {
                res.cookie("account", account);
                res.cookie("account_secret", secret);

                if (req.param("returnTo") === undefined) {
                    res.send("Successfully authenticated");
                } else {
                    var url = urlUtil.parse(req.param("returnTo"));
                    if (url.query) {
                        url.query.token = token;
                    } else {
                        url.query = {
                            token: token
                        };
                    }

                    res.redirect(urlUtil.format(url));
                }
            }
        });
    }).catch(function(e) {
        console.log(e);
        console.log(e.stack);
        res.status(500).send(e.toString());
    }).done();
});

app.post('/token', function(req, res) {
    var token = req.param('token') || req.body.token;

    if (token === undefined) {
        return res.status(400).send('token parameter is required');
    }

    try {
        authorizeToken(token, req.param('restricted')).then(function(auth) {
            console.log(auth);
            res.send(auth);
        }).catch(function(e) {
            console.log(e);
            console.log(e.stack);
            res.status(500).send(e.toString());
        }).done();
    } catch(e) {
        console.log(e);
        console.log(e.stack);

        res.status(401).send(e.toString());
    }
});

var server = http.createServer(app);
server.listen(port);
console.log("server ready");
