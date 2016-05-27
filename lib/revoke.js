// third-party dependencies
const jwt   = require('jsonwebtoken');

// internal dependencies
const InvalidTokenError = require('./errors').InvalidTokenError;

module.exports = function (hToken, options) {
  const TokenBlacklistEntry = hToken.models.TokenBlacklistEntry;

  return function (token) {

    if (!token) { throw new InvalidTokenError('token must be a string'); }

    // decode the token
    return hToken.verify(token)
      .then((decoded) => {
        var jti = decoded.jti;

        if (!jti) {
          return Promise.reject(new InvalidTokenError('the token has no jti'));
        }

        var tokenBlacklistEntry = new TokenBlacklistEntry({
          tokenId: jti
        });

        return tokenBlacklistEntry.save();
      });
  };
};