// native dependencies

// external dependencies
const mongoose  = require('mongoose');

/**
 * Function that starts the host server
 */
function createHToken(options) {
  if (!options.mongooseConnection) { throw new Error('mongooseConnection is required'); }

  var conn = options.mongooseConnection;

  var hToken = {};

  // load models
  hToken.models = {};
  hToken.models.Token               = require('./models/token')(conn, options);
  hToken.models.TokenBlacklistEntry = require('./models/token-blacklist-entry')(conn, options);

  hToken.generate = require('./methods/generate')(hToken, options);
  hToken.verify = require('./methods/verify')(hToken, options);
  hToken.revoke = require('./methods/revoke')(hToken, options);

  return hToken;
}

createHToken.errors = require('./errors');

module.exports = createHToken;