const assert = require('assert');
const should = require('should');

const mongoose = require('mongoose');

const hToken = require('../../lib');

// auxiliary
const dbConn = require('../auxiliary/db-conn');

const REQUIRED_OPTIONS = {
  mongooseConnection: dbConn.mongooseConnection,
  tokenModelName: 'TestToken',
  secret: 'fake-secret',
  issuer: 'test-issuer',
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
  
  it('should initialize correctly in case all required options are passed', function () {
    var ht = hToken(REQUIRED_OPTIONS);
  });
});