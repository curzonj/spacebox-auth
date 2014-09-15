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
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

var tokens = {};

app.get('/auth', function(req, res) {
    console.log("Cookies: ", req.cookies);
    var account = req.cookies.account;
    if (account === undefined) {
        account = uuidGen.v1();
        res.cookie("account", account);
    }
    var token = uuidGen.v4();
    tokens[token] = {
        account: account,
        expires: new Date().getTime() + 5000
    };

    var url = urlUtil.parse(req.param("returnTo"));
    if (url.query) {
        url.query.token = token;
    } else {
        url.query = { token: token };
    }

    res.redirect(urlUtil.format(url));
});

app.post('/token', function(req, res) {
    var token = req.param('token');
    res.send(tokens[token]);
});

var server = http.createServer(app);
server.listen(port);
console.log("server ready");
