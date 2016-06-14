const assert = require('assert');
const should = require('should');

const mongoose = require('mongoose');

const hToken = require('../../lib');

// auxiliary
const aux = require('../auxiliary');

const REQUIRED_OPTIONS = {
  mongooseConnection: mongoose.createConnection(aux.TEST_DB_URI),
  tokenModelName: 'TestToken',
  secret: 'fake-secret',
  issuer: 'test-issuer',
  defaultTokenExpiry: '1h',
};

function clone(obj) {
  var cloneObj = {};

  for (prop in obj) {
    if (obj.hasOwnProperty(prop)) {
      cloneObj[prop] = obj[prop];
    }
  }

  return cloneObj;
}

describe('initialization', function () {
  it('should require mongooseConnection option', function () {
    var options = clone(REQUIRED_OPTIONS);
    delete options.mongooseConnection;

    assert.throws(function () {
      var ht = hToken(options);
    });
  });

  it('should require tokenModelName option', function () {
    var options = clone(REQUIRED_OPTIONS);
    delete options.tokenModelName;

    assert.throws(function () {
      var ht = hToken(options);
    });
  });

  it('should require secret option', function () {
    var options = clone(REQUIRED_OPTIONS);
    delete options.secret;

    assert.throws(function () {
      var ht = hToken(options);
    });
  });

  it('should require issuer option', function () {
    var options = clone(REQUIRED_OPTIONS);
    delete options.issuer;

    assert.throws(function () {
      var ht = hToken(options);
    });
  });

  it('should require defaultTokenExpiry option', function () {
    var options = clone(REQUIRED_OPTIONS);
    delete options.defaultTokenExpiry;

    assert.throws(function () {
      var ht = hToken(options);
    });
  });
  
  it('should initialize correctly in case all required options are passed', function () {
    var ht = hToken(REQUIRED_OPTIONS);
  });
});