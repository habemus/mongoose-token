// third-party dependencies
const MongoClient = require('mongodb').MongoClient;
const mongoose = require('mongoose');

// constant
const TEST_DB_URI = 'mongodb://localhost:27017/h-token-test-db';


// set mongoose to debug mode
if (process.env.DEBUG === 'TRUE') {
  mongoose.set('debug', true);
}

exports.mongodbConn = MongoClient.connect(TEST_DB_URI);
exports.mongooseConnection = mongoose.connect(TEST_DB_URI);