// third-party dependencies
const jwt   = require('jsonwebtoken');

// internal dependencies
const InexistentToken = require('../errors').InexistentToken;
const mongoose = require('mongoose');
const ObjectId = mongoose.Types.ObjectId;

module.exports = function (hToken, options) {
  const Token               = hToken.models.Token;
  const TokenBlacklistEntry = hToken.models.TokenBlacklistEntry;

  return function (tokenId) {

    if (!ObjectId.isValid(tokenId)) { throw new TypeError('tokenId is not valid'); }

    return Promise.resolve(Token.findOne({ _id: tokenId }))
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