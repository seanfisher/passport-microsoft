/* global describe, it, expect, before */
/* jshint expr: true */

var chai = require('chai'),
  MicrosoftStrategy = require('../lib/strategy');

describe('Strategy', function () {
  describe('constructed', function () {
    var strategy = new MicrosoftStrategy(
      {
        clientID: 'ABC123',
        clientSecret: 'secret',
      },
      function () {}
    );

    it('should be named microsoft', function () {
      expect(strategy.name).to.equal('microsoft');
    });
  });

  describe('constructed with undefined options', function () {
    it('should throw', function () {
      expect(function () {
        var strategy = new MicrosoftStrategy(undefined, function () {});
      }).to.throw(Error);
    });
  });

  describe('authorization request with display parameter', function () {
    var strategy = new MicrosoftStrategy(
      {
        clientID: 'ABC123',
        clientSecret: 'secret',
      },
      function () {}
    );

    var url;

    before(function (done) {
      chai.passport
        .use(strategy)
        .redirect(function (u) {
          url = u;
          done();
        })
        .request(function (req) {})
        .authenticate({ display: 'mobile' });
    });

    it('should be redirected', function () {
      expect(url).to.equal(
        'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?display=mobile&response_type=code&client_id=ABC123'
      );
    });
  });

  describe('authorization request with reauthorization parameters', function () {
    var strategy = new MicrosoftStrategy(
      {
        clientID: 'ABC123',
        clientSecret: 'secret',
      },
      function () {}
    );

    var url;

    before(function (done) {
      chai.passport
        .use(strategy)
        .redirect(function (u) {
          url = u;
          done();
        })
        .request(function (req) {})
        .authenticate({ authType: 'reauthenticate', authNonce: 'foo123' });
    });

    it('should be redirected', function () {
      expect(url).to.equal(
        'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?response_type=code&client_id=ABC123'
      );
    });
  });

  describe('failure caused by user denying request', function () {
    var strategy = new MicrosoftStrategy(
      {
        clientID: 'ABC123',
        clientSecret: 'secret',
      },
      function () {}
    );

    var info;

    before(function (done) {
      chai.passport
        .use(strategy)
        .fail(function (i) {
          info = i;
          done();
        })
        .request(function (req) {
          req.query = {};
          req.query.error = 'access_denied';
          req.query.error_code = '200';
          req.query.error_description = 'Permissions error';
          req.query.error_reason = 'user_denied';
        })
        .authenticate();
    });

    it('should fail with info', function () {
      expect(info).to.not.be.undefined;
      expect(info.message).to.equal('Permissions error');
    });
  });

  describe('error caused by invalid code sent to token endpoint (note: error format does not conform to OAuth 2.0 specification)', function () {
    var strategy = new MicrosoftStrategy(
      {
        clientID: 'ABC123',
        clientSecret: 'secret',
      },
      function () {}
    );

    strategy._oauth2.getOAuthAccessToken = function (code, options, callback) {
      return callback({
        statusCode: 400,
        data: '{"error":{"message":"Invalid verification code format.","type":"OAuthException","code":100}}',
      });
    };

    var err;

    before(function (done) {
      chai.passport
        .use(strategy)
        .error(function (e) {
          console.log(e);
          err = e;
          done();
        })
        .request(function (req) {
          req.query = {};
          req.query.code = 'SplxlOBeZQQYbYS6WxSbIA+ALT1';
        })
        .authenticate();
    });

    it('should error', function () {
      expect(err.constructor.name).to.equal('TokenError');
    });
  }); // error caused by invalid code sent to token endpoint

  describe('error caused by invalid code sent to token endpoint (note: error format conforms to OAuth 2.0 specification, though this is not the current behavior of the Microsoft implementation)', function () {
    var strategy = new MicrosoftStrategy(
      {
        clientID: 'ABC123',
        clientSecret: 'secret',
      },
      function () {}
    );

    // inject a "mock" oauth2 instance
    strategy._oauth2.getOAuthAccessToken = function (code, options, callback) {
      return callback({
        statusCode: 400,
        data: '{"error":"invalid_grant","error_description":"The provided value for the input parameter \'code\' is not valid."} ',
      });
    };

    var err;

    before(function (done) {
      chai.passport
        .use(strategy)
        .error(function (e) {
          err = e;
          done();
        })
        .request(function (req) {
          req.query = {};
          req.query.code = 'SplxlOBeZQQYbYS6WxSbIA+ALT1';
        })
        .authenticate();
    });

    it('should error', function () {
      expect(err.constructor.name).to.equal('TokenError');
      expect(err.message).to.equal(
        'The provided value for the input parameter \'code\' is not valid.'
      );
      expect(err.code).to.equal('invalid_grant');
    });
  }); // error caused by invalid code sent to token endpoint
});
