// third-party
const mongoose = require('mongoose');

// constants
const Schema = mongoose.Schema;

var tokenBlacklistEntrySchema = new Schema({
  jti: {
    type: String,
    required: true,
  },

  tokenExp: {
    type: Date,
    required: true,
    index: {
      // token db entries expire once the exp date is reached
      expires: 0,
    }
  },
});

// takes the connection and options and returns the model
module.exports = function (conn, options) {

  // this verification has already been run in lib/models/token
  // if (!options.tokenModelName) { throw new Error('options.tokenModelName is required'); }

  var tokenBlacklistModelName = options.tokenModelName + 'BlacklistEntry';

  var TokenBlacklistEntry = conn.model(tokenBlacklistModelName, tokenBlacklistEntrySchema);
  
  return TokenBlacklistEntry;
};