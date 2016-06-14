// third-party dependencies
const jwt = require('jsonwebtoken');
const _pick = require('lodash.pick');
const ms = require('ms');
const uuid = require('node-uuid');
const Bluebird = require('bluebird');

const mongoose = require('mongoose');

const ValidationError = mongoose.Error.ValidationError;
const ValidatorError = mongoose.Error.ValidatorError;

const _jwtSign = Bluebird.promisify(jwt.sign);

// own
const errors = require('../errors');

// constants
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
  // models
  const Token = hToken.models.Token;

  // constants
  const JWT_ALG              = options.jwtAlgorithm || DEFAULT_JWT_ALG;
  const ISSUER               = options.issuer;
  const SECRET               = options.secret;
  const DEFAULT_TOKEN_EXPIRY = _getTimeInSeconds(options.defaultTokenExpiry);

  return function (jwtPayload, jwtOptions) {

    jwtPayload = jwtPayload || {};

    // check for required options InvalidOptionError
    if (!jwtOptions.subject) { return Bluebird.reject(new errors.InvalidOptionError('subject', 'subject is required')); }

    // token issue time in SECONDS
    // PRECISION MUST BE at the SECONDS LEVEL
    var issuedAt = Math.floor(Date.now() / 1000);
    var issuedAtMs = issuedAt * 1000;

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
      _signOptions.expiresIn = DEFAULT_TOKEN_EXPIRY;
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

      // mongoose cast requires milliseconds
      iat: issuedAtMs,
      exp: issuedAtMs + (_signOptions.expiresIn * 1000),

      // use mongodb's _id for jti
    };

    if (_signOptions.notBefore) {
      tokenDbEntryData.nbf = issuedAtMs + (_signOptions.notBefore * 1000);
    }

    // create entry on db
    var tokenEntry = new Token(tokenDbEntryData);

    return Bluebird.resolve(tokenEntry.save())
      .then((createdTokenEntry) => {

        // set the iat (issuedAt) property of the payload
        // in order to override the default issuedAt
        jwtPayload.iat = issuedAt;

        // use the jti that was verified as unique by the database
        _signOptions.jwtid = createdTokenEntry._id.toString();

        return _jwtSign(jwtPayload, SECRET, _signOptions);
      });
  };
}