const assert = require('assert');

// third-party dependencies
const should = require('should');
const jwt = require('jsonwebtoken');

// lib
const hToken = require('../../lib');

// auxiliary
const dbConn = require('../auxiliary/db-conn');

const SECRET = 'test-secret';
const H_TOKEN_OPTIONS = {
  mongooseConnection: dbConn.mongooseConnection,
  tokenModelName: 'TestToken',
  secret: SECRET,
  issuer: 'test-issuer',
};

describe('hToken#generate', function () {

  before(function (done) {
    // drop database
    dbConn.mongodbConn
      .then((db) => {
        return db.dropDatabase();
      })
      .then(() => {
        done();
      })
      .catch(done);
  });

  after(function () {

  });

  it('should generate a JWT token', function (done) {
    var ht = hToken(H_TOKEN_OPTIONS);

    var payload = {
      someData: 'someValue'
    };

    var options = {
      subject: 'someone'
    };

    ht.generate(payload, options)
      .then((token) => {
        token.should.be.a.String();

        jwt.verify(token, SECRET, (err, decoded) => {
          if (err) {
            done(err);
            return;
          }

          decoded.someData.should.equal(payload.someData);

          done();
        });
      })
      .catch((err) => {
        done(err);
      });
  });
});