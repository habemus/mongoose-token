const assert = require('assert');

// third-party dependencies
const should = require('should');
const jwt = require('jsonwebtoken');

// lib
const hToken = require('../../lib');

// auxiliary
const aux = require('../auxiliary');

const SECRET = 'test-secret';

describe('hToken#verify', function () {

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

  it('should require token to be a string', function () {
    assert.throws(function () {
      ASSETS.ht.verify(false);
    }, hToken.errors.InvalidTokenError);
  });

  it('should reject forged tokens', function (done) {

    var ht = ASSETS.ht;

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
    var ht = ASSETS.ht;

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