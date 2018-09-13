const assert = require('assert');
const { promisify } = require('util')

// third-party dependencies
const should = require('should');
const jwt = require('jsonwebtoken');
const ms  = require('ms');

const _jwtVerify = promisify(jwt.verify);

// lib
const hToken = require('../../lib');

// auxiliary
const aux = require('../auxiliary');

const SECRET = 'test-secret';

function _wait(ms) {
  return new Promise((resolve, reject) => {
    setTimeout(resolve, ms);
  });
}

describe('hToken#generate', function () {

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

  it('should generate a JWT token', function (done) {
    var payload = {
      someData: 'someValue'
    };

    var options = {
      subject: 'someone'
    };

    aux.ensurePromise(ASSETS.ht.generate(payload, options))
      .then((token) => {
        token.should.be.a.String();

        return _jwtVerify(token, SECRET);
      })
      .then((decoded) => {
        // payload
        decoded.someData.should.equal(payload.someData);

        // options
        decoded.iss.should.be.equal('test-issuer');
        decoded.sub.should.equal(options.subject);
        decoded.jti.should.be.instanceof(String);
        decoded.iat.should.be.instanceof(Number);
        decoded.exp.should.be.instanceof(Number);

        should(decoded.exp > decoded.iat).be.true();

        // should have used the defaultTokenExpiry value
        // make some room for precision
        var expDiff = decoded.exp - decoded.iat;
        should(expDiff > 990).be.true();
        should(expDiff < 1100).be.true();

        Object.keys(decoded).length.should.equal(6);

        done();
      })
      .catch((err) => {
        done(err);
      });
  });

  it('should expire in X amount of time', function (done) {
    this.timeout(15 * 1000);

    var payload = {
      someData: 'someValue'
    };

    var options = {
      subject: 'someone',

      expiresIn: '10s',
    };

    var _token;


    aux.ensurePromise(ASSETS.ht.generate(payload, options))
      .then((token) => {
        _token = token;
        token.should.be.a.String();

        // immediately verify
        return _jwtVerify(token, SECRET);
      })
      .then((decoded) => {
        decoded.someData.should.equal(payload.someData);

        // expiry must be in the future
        should(decoded.iat < decoded.exp);

        // wait 9 seconds
        return _wait(9 * 1000);

      })
      .then(() => {
        return _jwtVerify(_token, SECRET);

      })
      .then((decoded) => {
        decoded.someData.should.equal(payload.someData);

        return _wait(5 * 1000);
      })
      .then(() => {
        return _jwtVerify(_token, SECRET);
      })
      .then(() => {
        done(new Error('error expected'));
      }, (err) => {
        err.name.should.equal('TokenExpiredError');

        done();
      })
      .catch((err) => {
        done(err);
      });

  });

  it('should not be ready before X amount of time', function (done) {
    this.timeout(15 * 1000);

    var payload = {
      someData: 'someValue'
    };

    var options = {
      subject: 'someone',

      notBefore: '10s',
    };

    var _token;


    aux.ensurePromise(ASSETS.ht.generate(payload, options))
      .then((token) => {
        _token = token;
        token.should.be.a.String();

        var a = jwt.decode(token);

        // immediately verify
        return _jwtVerify(token, SECRET);
      })
      .then(() => {
        done(new Error('error expected'));
      }, (err) => {
        err.name.should.equal('NotBeforeError');

        return _wait(11 * 1000);
      })
      .then(() => {
        return _jwtVerify(_token, SECRET);
      })
      .then((decoded) => {
        decoded.someData.should.equal(payload.someData);

        // notBefore must be in the future
        should(decoded.iat < decoded.nbf);

        done();
      })
      .catch((err) => {
        done(err);
      });

  });

  it('should require the subject option', function (done) {
    var payload = {};

    var options = {};

    aux.ensurePromise(ASSETS.ht.generate(payload, options))
      .then((token) => {
        done(new Error('error expected'));
      }, (err) => {
        err.should.be.instanceof(hToken.errors.InvalidOptionError);
        err.path.should.equal('subject');

        done();
      })
      .catch(done);
  });

  it('should store the token in the database', function (done) {

    var payload = {
      someData: 'someValue'
    };

    var options = {
      subject: 'someone',
      audience: ['another-api', 'yet-another-api'],
      expiresIn: '1d',
      notBefore: '1s',
    };

    aux.ensurePromise(ASSETS.ht.generate(payload, options))
      .then((token) => {
        return ASSETS.db.collection('testtokens').find().toArray();
      })
      .then((entries) => {

        entries.length.should.equal(1);
        tokenDbEntry = entries[0];

        // calculate the amount of milliseconds since 1970 of iat
        var iatTime = tokenDbEntry.iat.getTime();

        tokenDbEntry._id.toString().should.be.instanceof(String);
        tokenDbEntry.iss.should.equal('test-issuer');
        tokenDbEntry.sub.should.equal(options.subject);
        tokenDbEntry.aud.should.eql(['another-api', 'yet-another-api']);
        tokenDbEntry.exp.should.eql(new Date(iatTime + ms('1d')));
        tokenDbEntry.nbf.should.eql(new Date(iatTime + ms('1s')));
        tokenDbEntry.iat.should.be.instanceof(Date);

        // 8 properties: _id, iss, sub, aud, exp, nbf, iat and mongodb's `__v`
        Object.keys(tokenDbEntry).length.should.equal(8);

        done();
      })
      .catch(done);
  });
  
  it('should generate without payload', function (done) {
    var options = {
      subject: 'someone'
    };

    aux.ensurePromise(ASSETS.ht.generate(undefined, options))
      .then((token) => {
        token.should.be.a.String();

        return _jwtVerify(token, SECRET);
      })
      .then((decoded) => {
        // options
        decoded.iss.should.be.equal('test-issuer');
        decoded.sub.should.equal(options.subject);
        decoded.jti.should.be.instanceof(String);
        decoded.iat.should.be.instanceof(Number);
        decoded.exp.should.be.instanceof(Number);

        Object.keys(decoded).length.should.equal(5);

        done();
      })
      .catch((err) => {
        done(err);
      });

  });

});