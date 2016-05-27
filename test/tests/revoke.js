const assert = require('assert');

// third-party dependencies
const should = require('should');
const jwt = require('jsonwebtoken');

const MongoClient = require('mongodb').MongoClient;
const mongoose = require('mongoose');

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

describe('hToken#revoke', function () {

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

  it('should require the decoded token to have jti field', function (done) {
    var ht = hToken(H_TOKEN_OPTIONS);

    // create a correctly signed token without jti
    var token = jwt.sign({}, SECRET);

    ht.revoke(token)
      .then(() => {
        done(new Error('should not allow token without jti'));
      })
      .catch((err) => {
        err.should.be.instanceof(hToken.errors.InvalidTokenError);
        done();
      });
  });

  it('should require the token to be a string', function () {
    var ht = hToken(H_TOKEN_OPTIONS);

    assert.throws(function () {
      ht.revoke(null);
    }, hToken.errors.InvalidTokenError);
  });

  it('should revoke a JWT token', function (done) {
    var ht = hToken(H_TOKEN_OPTIONS);

    var payload = {
      someData: 'someValue'
    };

    var options = {
      subject: 'someone'
    };

    // store the token for later usage
    var _token;

    ht.generate(payload, options)
      .then((token) => {
        _token = token;
        token.should.be.a.String();

        // revoke the token
        return ht.revoke(token);

      })
      .then(() => {

        // attempting to verify the token throws error
        return ht.verify(_token);
      })
      .then(() => {
        done(new Error('should not be capable of decoding'))
      }, (err) => {
        // error is expected
        err.should.be.instanceof(hToken.errors.InvalidTokenError);
        done();
      })
      .catch((err) => {
        done(err);
      });
  });
});