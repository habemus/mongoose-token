// native dependencies
const util = require('util');

function HTokenError(message) {
  Error.call(this);
  this.message = message;
};
util.inherits(HTokenError, Error);
HTokenError.prototype.name = 'HTokenError';

function InvalidTokenError(reason, message) {
  HTokenError.call(this, message);

  this.reason = reason;
};
util.inherits(InvalidTokenError, HTokenError);
InvalidTokenError.prototype.name = 'InvalidTokenError';

function InvalidOptionError(path, message) {
  HTokenError.call(this, message);

  this.path = path;
}
util.inherits(InvalidOptionError, HTokenError);
InvalidOptionError.prototype.name = 'InvalidOptionError';

function InexistentToken(message) {
  HTokenError.call(this, message);
}
util.inherits(InexistentToken, HTokenError);
InexistentToken.prototype.name = 'InexistentToken';

// jsonwebtoken lib errors and error messages
// https://www.npmjs.com/package/jsonwebtoken#errors--codes

exports.HTokenError = HTokenError;
exports.InvalidTokenError = InvalidTokenError;
exports.InvalidOptionError = InvalidOptionError;
exports.InexistentToken = InexistentToken;