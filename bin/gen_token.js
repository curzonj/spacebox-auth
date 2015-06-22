#!/usr/bin/env node

'use strict';

var jwt = require('jsonwebtoken')

console.log(jwt.sign({
    account: process.argv[2],
    privileged: true,
}, process.env.JWT_SIG_KEY, {
    expiresInSeconds: 3600
}))

