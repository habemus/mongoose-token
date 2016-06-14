const assert = require('assert');

// third-party dependencies
const should = require('should');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const ObjectId = mongoose.Types.ObjectId;
const ora = require('ora');

// lib
const hToken = require('../../lib');

// auxiliary
const aux = require('../auxiliary');

const SECRET = 'test-secret';

describe('hToken token db auto-expiry', function () {

  var ASSETS;

  beforeEach(function (done) {
    aux.setup()
      .then((assets) => {
        ASSETS = assets;

        ASSETS.ht = hToken({
          mongooseConnection: ASSETS.mongooseConnection,
          tokenModelName: 'TestToken',
          secret: SECRET,
          issuer: 'test-issuer',
          // 1000 seconds
          defaultTokenExpiry: 1000,
        });

        done();
      })
      .catch(done);
  });

  afterEach(function (done) {
    aux.teardown().then(done);
  });

  it('tokens stored in the database should be auto expired by the TTL index', function (done) {
    

    // lets wait for at most 90 seconds
    // mongodb process for removing TTL expired entries runs 
    // every 60 seconds
    // https://docs.mongodb.com/manual/core/index-ttl/#timing-of-the-delete-operation
    this.timeout(90 * 1000);

    var payload = {
      someData: 'someValue'
    };

    var options = {
      subject: 'someone',

      // make it expire in 10 seconds
      expiresIn: '10s',
    };

    // store decoded token for usage accross multiple phases
    var _decoded;

    ASSETS.ht.generate(payload, options)
      .then((token) => {
        token.should.be.a.String();

        return new Promise((resolve, reject) => {
          jwt.verify(token, SECRET, (err, decoded) => {
            if (err) {
              reject(err);
              return;
            }

            // check some data about the token
            decoded.someData.should.equal(payload.someData);

            resolve(decoded);
          });
        });

      })
      .then((decoded) => {
        _decoded = decoded;

        return ASSETS.db.collection('testtokens').find({ _id: new ObjectId(decoded.jti) }).toArray();
      })
      .then((dbTokens) => {
        dbTokens.length.should.equal(1);

        var attemptCount = 0;
        var interval = setInterval(function () {

          ++attemptCount;
          ASSETS.db.collection('testtokens').find({ _id: new ObjectId(_decoded.jti) })
            .toArray()
            .then((dbTokens) => {
              if (dbTokens.length === 0) {
                clearInterval(interval);
                done();
              } else {
                console.log(attemptCount + ') ' + attemptCount * 5 + ' seconds: found ' + dbTokens.length);
              }
            });

        }, 5 * 1000);
      })
      .catch((err) => {
        done(err);
      });
  });
});