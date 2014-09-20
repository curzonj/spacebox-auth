'use strict';

var urlUtil = require("url");
var http = require("http");
var express = require("express");
var logger = require('morgan');
var bodyParser = require('body-parser');
var uuidGen = require('node-uuid');
var cookieParser = require('cookie-parser');
var pg = require('pg');

var app = express();
var port = process.env.PORT || 5000;

app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: false
}));
app.use(cookieParser());

var tokens = {};
var accounts = {
    // Obviously only going to be here during development.
    // For deployment the auth server will be backed by
    // a database and you can creating these during deployment.
    "08b9cfde-5612-486e-bb34-78605e5f0375": {
        "secret": "40a58204-1c50-41fc-bb66-89a357b08e1c",
        "privileged": true
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

app.post('/accounts', function(req, res) {
    if (!isAPIRequest(req)) {
        return res.status(400).send("json requests only");
    }

    var account = uuidGen.v1();
    accounts[account] = {
        secret: req.body.secret,
        privileged: (req.body.privileged === true)
    };

    res.send({
        account: account
    });
});

app.get('/auth', function(req, res) {
    var account, secret;

    if (isAPIRequest(req)) {
        var basic_auth = getBasicAuth(req);
        if (basic_auth.user === undefined) return res.sendStatus(401);

        account = basic_auth.user;
        secret = basic_auth.password;
    } else {
        secret = req.cookies.account_secret;
        account = req.cookies.account;

        if (account === undefined) {
            account = uuidGen.v1();
            secret = uuidGen.v4();

            accounts[account] = {
                secret: secret
            };
        }
    }

    var account_data = accounts[account];

    if (account_data === undefined || account_data.secret != secret) {
        return res.sendStatus(401);
    }

    var token = uuidGen.v4();
    var ttl = req.param('ttl') || 300; // default 5min ttl
    var expires = new Date().getTime() + (ttl * 1000);

    tokens[token] = {
        account: account,
        privileged: (account_data.privileged === true),
        expires: expires
    };

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

app.post('/token', function(req, res) {
    var token = req.param('token') || req.body.token;
    var restricted = req.param('restricted');

    var authorization = tokens[token];
    var now = new Date().getTime();

    if (authorization === undefined || authorization.expires < now) {
        return res.sendStatus(401);
    }

    if ((restricted === true || restricted == 'true') &&
        authorization.privileged !== true) {
        console(authorization.account, "rejected for restricted endpoint");
        return res.sendStatus(401);
    }

    // If you are privileged, you can pretend to be anybody you want
    if (authorization.privileged === true && token.indexOf(':') > 0) {
        var parts = token.split(':');
        authorization.account = parts[1];
    }

    // TODO include a list of all the groups this person belongs to
    res.send({
        account: authorization.account,
        expires: authorization.expires, // this is so they can cache it
        privileged: (authorization.privileged === true),
        groups: []
    });
});

var server = http.createServer(app);
server.listen(port);
console.log("server ready");
