/* global describe, it, expect */

var strategy = require('..');

describe('passport-microsoft', function () {
  it('should export Strategy constructor', function () {
    expect(strategy.Strategy).to.be.a('function');
  });
});
