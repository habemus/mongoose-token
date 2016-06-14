// third-party dependencies
const jwt   = require('jsonwebtoken');

// internal dependencies
const InvalidTokenError = require('../errors').InvalidTokenError;

module.exports = function (hToken, options) {
  const TokenBlacklistEntry = hToken.models.TokenBlacklistEntry;

  return function (tokenId) {

    if (typeof tokenId !== 'string') { throw new TypeError('tokenId must be a string'); }

    var tokenBlacklistEntry = new TokenBlacklistEntry({
      jti: tokenId
    });

    return tokenBlacklistEntry.save();
  };
};