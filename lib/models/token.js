// third-party
const mongoose = require('mongoose');

// constants
const Schema = mongoose.Schema;

var tokenSchema = new Schema({

});

// takes the connection and options and returns the model
module.exports = function (conn, options) {

  if (!options.tokenModelName) { throw new Error('options.tokenModelName is required'); }

  var Token = conn.model(options.tokenModelName, tokenSchema);
  
  return Token;
};