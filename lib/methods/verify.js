// third-party dependencies
const jwt = require('jsonwebtoken');
const Bluebird = require('bluebird');

const _jwtVerify = Bluebird.promisify(jwt.verify);

const InvalidTokenError = require('../errors').InvalidTokenError;

module.exports = function (hToken, options) {
  const SECRET              = options.secret;
  const TokenBlacklistEntry = hToken.models.TokenBlacklistEntry;

  return function (token) {
    if (typeof token !== 'string') { throw new InvalidTokenError('token must be a string'); }

    /**
     * https://www.npmjs.com/package/jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback
     * 
     * algorithms: List of strings with the names of the allowed algorithms. For instance, ["HS256", "HS384"].
     * audience: if you want to check audience (aud), provide a value here
     * issuer (optional): string or array of strings of valid values for the iss field.
     * ignoreExpiration: if true do not validate the expiration of the token.
     * ignoreNotBefore...
     * subject: if you want to check subject (sub), provide a value here
     * clockTolerance: number of second to tolerate when checking the nbf and exp claims, to deal with small clock differences among different servers
     * 
     * @type {Object}
     */
    var verifyOptions = {
      // algorithms:
      // audience
      issuer: options.issuer
      // ignoreExpiration
      // ignoreNotBefore
      // subject
      // clockTolerance
    };

    var _decoded;

    return _jwtVerify(token, SECRET, verifyOptions)
      .then((decoded) => {

        _decoded = decoded;

        // check if the token has been revoked
        return TokenBlacklistEntry.findOne({
          jti: decoded.jti,
        });
 
      })
      .catch((err) => {
        var errMsg = err.message;

        if (err.name === 'JsonWebTokenError') {
          /**
           * https://www.npmjs.com/package/jsonwebtoken#jsonwebtokenerror
           * 
           * name: 'JsonWebTokenError' (from jsonwebtoken lib)
           * message:
           * 'jwt malformed'
           * 'jwt signature is required'
           * 'invalid signature'
           * 'jwt audience invalid. expected: [OPTIONS AUDIENCE]'
           * 'jwt issuer invalid. expected: [OPTIONS ISSUER]'
           * 'jwt id invalid. expected: [OPTIONS JWT ID]'
           * 'jwt subject invalid. expected: [OPTIONS SUBJECT]'
           */
          if (errMsg === 'jwt malformed') {
            return Bluebird.reject(new InvalidTokenError('MalformedJWT'));
          } else if (errMsg === 'invalid signature') {
            return Bluebird.reject(new InvalidTokenError('InvalidSignature'));
          } else if (errMsg.startsWith('jwt issuer')) {
            return Bluebird.reject(new InvalidTokenError('InvalidIssuer', errMsg));
          }

        } else if (err.name === 'TokenExpiredError') {

          /**
           * https://www.npmjs.com/package/jsonwebtoken#tokenexpirederror
           * 
           * name: 'TokenExpiredError'
           * message: 'jwt expired'
           * expiredAt: [ExpDate]
           */
          return Bluebird.reject(new InvalidTokenError(
            'TokenExpired',
            'expired at ' + err.expiredAt
          ));
        }

        // by default rethrow the error
        return Bluebird.reject(err);
      })
      .then((blacklistEntry) => {
        if (blacklistEntry) {
          return Bluebird.reject(new InvalidTokenError('The token is blacklisted'));
        } else {
          return _decoded;
        }
      });    
  };
};