#!/usr/bin/env node

'use strict';

var jwt = require('jsonwebtoken')

console.log(jwt.sign({
    account: process.argv[2],
    agent_id: process.argv[2],
    privileged: false,
}, process.env.JWT_SIG_KEY, {
    expiresInSeconds: 3600
}))

