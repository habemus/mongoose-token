// third-party dependencies
const jwt = require('jsonwebtoken');

const InvalidTokenError = require('./errors').InvalidTokenError;

module.exports = function (hToken, options) {
  if (!options.secret) { throw new TypeError('options.secret is required'); }

  const SECRET              = options.secret;
  const TokenBlacklistEntry = hToken.models.TokenBlacklistEntry;

  return function (token) {
    if (typeof token !== 'string') { throw new InvalidTokenError('token must be a string'); }

    var verifyOptions = {
      issuer: options.issuer
    };

    return new Promise((resolve, reject) => {
      // verifies secret and checks exp
      jwt.verify(token, SECRET, verifyOptions, (err, decoded) => {      
        if (err) {
          reject(new InvalidTokenError('Token verification failed'));
        } else {

          // check if the token has been revoked
          TokenBlacklistEntry.findOne({
            tokenId: decoded.jti,
          })
          .then((revocationEntry) => {
            if (revocationEntry) {
              reject(new InvalidTokenError('The token is blacklisted'));
            } else {
              resolve(decoded);
            }
          });
        }
      });
    });
    
  };
};