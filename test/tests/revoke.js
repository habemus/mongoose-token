const assert = require('assert');

// third-party dependencies
const should = require('should');
const jwt = require('jsonwebtoken');

const MongoClient = require('mongodb').MongoClient;
const mongoose = require('mongoose');

// lib
const hToken = require('../../lib');

// auxiliary
const aux = require('../auxiliary');

const SECRET = 'test-secret';

describe('hToken#revoke', function () {

  var ASSETS;

  before(function (done) {
    aux.setup()
      .then((assets) => {
        ASSETS = assets;

        ASSETS.ht = hToken({
          mongooseConnection: ASSETS.mongooseConnection,
          tokenModelName: 'TestToken',
          secret: SECRET,
          issuer: 'test-issuer'
        });

        done();
      });
  });

  after(function (done) {
    aux.teardown().then(done);
  });

  it('should require the tokenId to be a string', function () {
    assert.throws(function () {
      ASSETS.ht.revoke(null);
    }, TypeError);
  });

  it('should revoke a JWT token by id', function (done) {
    var payload = {
      someData: 'someValue'
    };

    var options = {
      subject: 'someone'
    };

    // store the token for later usage
    var _token;

    ASSETS.ht.generate(payload, options)
      .then((token) => {
        _token = token;
        token.should.be.a.String();

        var decoded = jwt.decode(token);

        // revoke the token
        return ASSETS.ht.revoke(decoded.jti);

      })
      .then(() => {

        // attempting to verify the token throws error
        return ASSETS.ht.verify(_token);
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