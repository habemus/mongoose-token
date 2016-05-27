// native
const util = require('util');

function HTokenError(message) {
  Error.call(this);

  this.message = message;
};

util.inherits(HTokenError, Error);

HTokenError.prototype.name = 'HTokenError';

module.exports = HTokenError;