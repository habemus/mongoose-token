// native
const util = require('util');

// internal dependencies
const HTokenError = require('./h-token-error');

function InvalidTokenError(message) {
  HTokenError.call(this);
  
  this.message = message;
};

util.inherits(InvalidTokenError, HTokenError);

InvalidTokenError.prototype.name = 'InvalidTokenError';

module.exports = InvalidTokenError;