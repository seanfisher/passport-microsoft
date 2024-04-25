/****************
 * IMPORTS
 */

var util = require('util');
var OAuth2Strategy = require('passport-oauth2');
var InternalOAuthError = require('passport-oauth2').InternalOAuthError;

/**
 * `Strategy` constructor.
 *
 * The Microsoft authentication strategy authenticates requests by delegating to
 * Microsoft using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientId`      	your Microsoft application's client id
 *   - `clientSecret`  	your Microsoft application's client secret
 *   - `callbackURL`   	URL to which Microsoft will redirect the user after granting authorization in your Microsoft Application
 *
 * Examples:
 *
 *     var MicrosoftStrategy = require('passport-microsoft').Strategy;
 *
 *     passport.use(new MicrosoftStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/microsoft/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */

function MicrosoftStrategy(options, verify) {
  options = options || {};
  const tenant = options.tenant || 'common';
  options.authorizationURL = options.authorizationURL || `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`;
  options.tokenURL = options.tokenURL || `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
  options.scopeSeparator = options.scopeSeparator || ' ';
  options.customHeaders = options.customHeaders || {};
  options.apiEntryPoint = options.apiEntryPoint || 'https://graph.microsoft.com';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'microsoft';
  this._graphApiVersion = options.graphApiVersion || 'v1.0';
  this._addUPNAsEmail = ('addUPNAsEmail' in options) ? options.addUPNAsEmail : false;
  this._apiEntryPoint = options.apiEntryPoint;
}

/**
 * Inherit from `OAuth2Strategy`.
 */

util.inherits(MicrosoftStrategy, OAuth2Strategy);

/**
 * Retrieve user profile from Microsoft Graph.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `microsoft`
 *   - `id`
 *   - etc..
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */

MicrosoftStrategy.prototype.authorizationParams = function(options) {
  var params = {};
  
  ['locale', 'display', 'prompt', 'login_hint', 'domain_hint'].forEach(function(name) {
    if (options[name]) {
      params[name] = options[name];
    }
  });

  return params;
};

MicrosoftStrategy.prototype.userProfile = function (accessToken, done) {
  var strategy = this;
  strategy._oauth2.useAuthorizationHeaderforGET(true);
  strategy._oauth2.get(
    `${strategy._apiEntryPoint}/${strategy._graphApiVersion}/me/`,
    accessToken,
    // eslint-disable-next-line no-unused-vars
    function (err, body, res) {

      if (err) {
        return done(new InternalOAuthError('failed to fetch user profile', err));
      }
      try {
        var json = JSON.parse(body);

        var profile = {
          provider: 'microsoft',
          name: {}
        };
        profile.id = json.id;
        profile.displayName = json.displayName;
        profile.name.familyName = json.surname;
        profile.name.givenName = json.givenName;
        profile.userPrincipalName = json.userPrincipalName;
        profile.emails = [];
        var isNotEmpty = str => str && typeof str === 'string' && str.trim().length;
        if (isNotEmpty(json.mail)) {
          profile.emails.push({ type: 'work', value: json.mail });
        }

        if (strategy._addUPNAsEmail && isNotEmpty(json.userPrincipalName)) {
          profile.emails.push({ type: 'work', value: json.userPrincipalName});
        }

        profile._raw = body;
        profile._json = json;

        done(null, profile);
      }
      catch (e) {
        done(e);
      }
    }
  );
};

/**
 * Expose `Strategy`.
 */

module.exports = MicrosoftStrategy;