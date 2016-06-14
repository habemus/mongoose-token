// third-party dependencies
const jwt = require('jsonwebtoken');
const _pick = require('lodash.pick');
const ms = require('ms');
const uuid = require('node-uuid');
const BPromise = require('bluebird');

const _jwtSign = BPromise.promisify(jwt.sign);

// own
const errors = require('../errors');

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

function _getTimeInSeconds(time) {
  return (typeof time === 'string') ? (ms(time) / 1000) : time;
}


module.exports = function (hToken, options) {
  if (typeof options.issuer !== 'string') { throw new TypeError('options.issuer must be a String'); }
  if (!options.secret) { throw new TypeError('options.secret is required'); }

  // models
  const Token = hToken.models.Token;

  // constants
  const JWT_ALG             = options.jwtAlgorithm || DEFAULT_JWT_ALG;
  const ISSUER              = options.issuer;
  const SECRET              = options.secret;
  const TOKEN_EXPIRY        = options.tokenExpiry ? 
    _getTimeInSeconds(options.tokenExpiry) : _getTimeInSeconds(DEFAULT_TOKEN_EXPIRY);

  return function (jwtPayload, jwtOptions) {

    jwtPayload = jwtPayload || {};
    jwtOptions = jwtOptions || {};

    // token issue time
    var issuedAt = Date.now();

    // pick only allowed options
    var _signOptions = _pick(jwtOptions, ALLOWED_JWT_OPTIONS);

    // set required options and parse
    _signOptions.issuer    = ISSUER;
    _signOptions.algorithm = JWT_ALG;

    // expiresIn is required
    // convert it to seconds
    if (_signOptions.expiresIn) {
      _signOptions.expiresIn = _getTimeInSeconds(_signOptions.expiresIn);
    } else {
      _signOptions.expiresIn = TOKEN_EXPIRY;
    }

    // notBefore is not required
    // if it is set, convert it to seconds as well
    if (_signOptions.notBefore) {
      _signOptions.notBefore = _getTimeInSeconds(_signOptions.notBefore);
    }

    var tokenDbEntryData = {
      iss: _signOptions.issuer,
      sub: _signOptions.subject,
      aud: _signOptions.audience,

      iat: issuedAt,
      exp: issuedAt + (_signOptions.expiresIn * 1000),

      // use mongodb's _id for jti
    };

    if (_signOptions.notBefore) {
      tokenDbEntryData.nbf = issuedAt + (_signOptions.notBefore * 1000);
    }

    // create entry on db
    var tokenEntry = new Token(tokenDbEntryData);

    return Promise.resolve(tokenEntry.save())
      .then((createdTokenEntry) => {

        // set the iat (issuedAt) property of the payload
        // in order to override the default issuedAt
        jwtPayload.iat = issuedAt;

        // use the jti that was verified as unique by the database
        _signOptions.jwtid = createdTokenEntry._id.toString();

        return _jwtSign(jwtPayload, SECRET, _signOptions);
      })
      .catch((err) => {
        // by default reject using the same error
        return Promise.reject(err);
      });
  };
}