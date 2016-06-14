const assert = require('assert');

// third-party dependencies
const should = require('should');
const jwt = require('jsonwebtoken');

// lib
const hToken = require('../../lib');

// auxiliary
const aux = require('../auxiliary');

const SECRET = 'test-secret';

describe('hToken#generate', function () {

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
      })
      .catch(done);
  });

  after(function (done) {
    aux.teardown().then(done);
  });

  it('should generate a JWT token', function (done) {
    var payload = {
      someData: 'someValue'
    };

    var options = {
      subject: 'someone'
    };

    ASSETS.ht.generate(payload, options)
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