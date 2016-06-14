// third-party dependencies
const jwt   = require('jsonwebtoken');

// internal dependencies
const InexistentToken = require('../errors').InexistentToken;
const Bluebird = require('bluebird');

module.exports = function (hToken, options) {
  const Token               = hToken.models.Token;
  const TokenBlacklistEntry = hToken.models.TokenBlacklistEntry;

  return function (tokenId) {

    if (typeof tokenId !== 'string') { throw new TypeError('tokenId must be a string'); }

    return Bluebird.resolve(Token.findOne({ _id: tokenId }))
      .then((token) => {
        if (!token) { return Promise.reject(new InexistentToken('token does not exist')); }

        var tokenBlacklistEntry = new TokenBlacklistEntry({
          jti: tokenId,

          tokenExp: token.get('exp'),
        });

        return tokenBlacklistEntry.save();
      });
  };
};