// third-party dependencies
const jwt = require('jsonwebtoken');
const Bluebird = require('bluebird');

const _jwtVerify = Bluebird.promisify(jwt.verify);

const InvalidTokenError = require('../errors').InvalidTokenError;

module.exports = function (hToken, options) {
  if (!options.secret) { throw new TypeError('options.secret is required'); }

  const SECRET              = options.secret;
  const TokenBlacklistEntry = hToken.models.TokenBlacklistEntry;

  return function (token) {
    if (typeof token !== 'string') { throw new InvalidTokenError('token must be a string'); }

    var verifyOptions = {
      issuer: options.issuer
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

        if (err.name === 'JsonWebTokenError') {
          var errMsg = err.message;

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
          } else if (errMsg === 'jwt signature is required') {
            return Bluebird.reject(new InvalidTokenError('SignatureRequired'));

          } else if (errMsg === 'invalid signature') {
            return Bluebird.reject(new InvalidTokenError('InvalidSignature'));

          } else if (errMsg.startsWith('jwt audience')) {
            return Bluebird.reject(new InvalidTokenError('InvalidAudience', errMsg));

          } else if (errMsg.startsWith('jwt issuer')) {
            return Bluebird.reject(new InvalidTokenError('InvalidIssuer', errMsg));

          } else if (errMsg.startsWith('jwt id')) {
            return Bluebird.reject(new InvalidTokenError('InvalidJwtId', errMsg));

          } else if (errMsg.startsWith('jwt subject')) {
            return Bluebird.reject(new InvalidTokenError('InvalisSubject', errMsg));

          }
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

    // return new Promise((resolve, reject) => {
    //   // verifies secret and checks exp
    //   jwt.verify(token, SECRET, verifyOptions, (err, decoded) => {      
    //     if (err) {
    //       reject(new InvalidTokenError('Token verification failed'));
    //     } else {

    //       // check if the token has been revoked
    //       TokenBlacklistEntry.findOne({
    //         jti: decoded.jti,
    //       })
    //       .then((revocationEntry) => {
    //         if (revocationEntry) {
    //           reject(new InvalidTokenError('The token is blacklisted'));
    //         } else {
    //           resolve(decoded);
    //         }
    //       });
    //     }
    //   });
    // });
    
  };
};