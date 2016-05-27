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

describe('hToken#verify', function () {

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

  it('should require token to be a string', function () {
    var ht = hToken(H_TOKEN_OPTIONS);

    assert.throws(function () {
      ht.verify(false);
    }, hToken.errors.InvalidTokenError);
  });

  it('should reject forged tokens', function (done) {

    var ht = hToken(H_TOKEN_OPTIONS);

    var forgedToken = jwt.sign({ foo: 'bar' }, 'FORGED-SECRET');

    ht.verify(forgedToken)
      .then((decoded) => {
        // should not happen!
        done(new Error('forgedToken was decoded'));
      })
      .catch((err) => {
        err.should.be.instanceof(hToken.errors.InvalidTokenError);
        done();
      });

  });

  it('should verify a JWT token', function (done) {
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

        return ht.verify(token)

      })
      .then((decoded) => {
        decoded.someData.should.equal(payload.someData);

        // sub should be taken from options
        decoded.sub.should.equal(options.subject);

        done();
      })
      .catch((err) => {
        done(err);
      });
  });
});