'use strict';

var Q = require('q'),
    C = require('spacebox-common')

Q.longStackSupport = true

var ctx = C.logging.create('api')

module.exports = {
    ctx: ctx,
    db: require('spacebox-common-native').db_select('auth', ctx)
}
