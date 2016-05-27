// third-party dependencies
const jwt = require('jsonwebtoken');
const _pick = require('lodash.pick');

// constants
const DEFAULT_TOKEN_EXPIRY = '1h';
const DEFAULT_JWT_ALG      = 'HS256';
const ALLOWED_JWT_OPTIONS  = [
  // 'algorithm',
  'expiresIn',
  'notBefore',
  'audience',
  // 'issuer',
  // 'jwtid',
  'subject',
  // 'noTimestamp',
  // 'header',
];


module.exports = function (hToken, options) {
  if (typeof options.issuer !== 'string') { throw new TypeError('options.issuer must be a String'); }
  if (!options.secret) { throw new TypeError('options.secret is required'); }

  // models
  const Token = hToken.models.Token;

  // constants
  const JWT_ALG             = options.jwtAlgorithm || DEFAULT_JWT_ALG;
  const ISSUER              = options.issuer;
  const SECRET              = options.secret;
  const TOKEN_EXPIRY        = options.tokenExpiry || DEFAULT_TOKEN_EXPIRY;

  return function (jwtPayload, jwtOptions) {

    jwtPayload = jwtPayload || {};
    jwtOptions = jwtOptions || {};

    // token issue time
    var issuedAt = Date.now();

    // pick only allowed options
    var _signOptions = _pick(jwtOptions, ALLOWED_JWT_OPTIONS);

    // set required options
    _signOptions.algorithm = JWT_ALG;
    _signOptions.issuer    = ISSUER;
    _signOptions.expiresIn = _signOptions.expiresIn || TOKEN_EXPIRY;

    // create entry on db
    var tokenEntry = new Token({
      issuer: _signOptions.issuer,
      subject: _signOptions.subject,
      audience: _signOptions.audience,
      expiresIn: _signOptions.expiresIn,
      notBefore: _signOptions.notBefore,
      issuedAt: issuedAt,
    });

    return tokenEntry.save()
      .then((createdTokenEntry) => {

        // set the iat (issuedAt) property of the payload
        // in order to override the default issuedAt
        jwtPayload.iat = issuedAt;

        // use the database generated id
        _signOptions.jwtid = createdTokenEntry._id.toString();

        return new Promise(function (resolve, reject) {
          jwt.sign(jwtPayload, SECRET, _signOptions, (err, token) => {

            if (err) {
              reject(err);
              return;
            } else {
              resolve(token);
              return;
            }
          });
        });
      });
  };
}