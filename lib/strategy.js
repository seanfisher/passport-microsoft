/****************
 * IMPORTS
 */
var https = require('https');
var { XMLParser } = require('fast-xml-parser');
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
 *   - `clientId`       your Microsoft application's client id
 *   - `clientSecret`   your Microsoft application's client secret
 *   - `DeveloperToken` the developer token from Microsoft Ads
 *   - `callbackURL`    URL to which Microsoft will redirect the user after granting authorization in your Microsoft Application
 *
 * Examples:
 *
 *     var MicrosoftStrategy = require('passport-microsoft').Strategy;
 *
 *     passport.use(new MicrosoftStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         DeveloperToken: 'shhh-its-also-a-secret'
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
  options.authorizationURL =
    options.authorizationURL ||
    `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`;
  options.tokenURL =
    options.tokenURL ||
    `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
  options.scopeSeparator = options.scopeSeparator || ' ';
  options.customHeaders = options.customHeaders || {};
  options.developerToken = options.developerToken || '';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'microsoft';
  this.developerToken = options.developerToken;
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
 * @param {String} developerToken
 * @param {Function} done
 * @api protected
 */

MicrosoftStrategy.prototype.authorizationParams = function (options) {
  var params = {};

  ['locale', 'display', 'prompt', 'login_hint', 'domain_hint'].forEach(
    function (name) {
      if (options[name]) {
        params[name] = options[name];
      }
    }
  );

  return params;
};

MicrosoftStrategy.prototype.userProfile = function (accessToken, done) {
  var soapRequest = this.constructSoapRequest(accessToken);

  var requestOptions = {
    hostname: 'clientcenter.api.bingads.microsoft.com',
    path: '/Api/CustomerManagement/v13/CustomerManagementService.svc',
    method: 'POST',
    headers: {
      'Content-Type': 'text/xml; charset=utf-8',
      SOAPAction: 'GetUser',
    },
  };

  var xmlParserOptions = {
    attributeNamePrefix: '',
    ignoreNameSpace: true,
    allowBooleanAttributes: true,
    trimValues: true,
  };

  var req = https.request(requestOptions, function (res) {
    var responseBody = '';

    res.setEncoding('utf-8');
    res.on('data', function (chunk) {
      responseBody += chunk;
    });

    res.on('end', function () {

      const parser = new XMLParser();
      let json;
      try {
        json = parser.parse(responseBody, xmlParserOptions);
      } catch (parseErr) {
        return done(
          new InternalOAuthError('Error parsing SOAP response', parseErr)
        );
      }

      try {
        const body = json['s:Envelope']['s:Body'];
        if (body['s:Fault']) {
          const fault = body['s:Fault'];
          let errorMessage =
            fault.faultstring || 'Error in response of SOAP request';

          if (
            fault.detail &&
            fault.detail.AdApiFaultDetail &&
            fault.detail.AdApiFaultDetail.Errors &&
            fault.detail.AdApiFaultDetail.Errors.AdApiError
          ) {
            errorMessage =
              fault.detail.AdApiFaultDetail.Errors.AdApiError.Message ||
              errorMessage;
          }

          throw new Error(errorMessage);
        }
        var user = body.GetUserResponse.User;

        var profile = {
          provider: 'microsoft',
          name: {
            givenName: user['a:Name']['a:FirstName'],
            familyName: user['a:Name']['a:LastName'],
          },
          emails: [{ type: 'work', value: user['a:ContactInfo']['a:Email'] }],
          id: user['a:Id'],
          displayName:
            user['a:Name']['a:FirstName'] + ' ' + user['a:Name']['a:LastName'],
          _raw: responseBody,
          _json: json,
        };


        done(null, profile);
      } catch (e) {
        done(new InternalOAuthError('Failed fetch user profile', e));
      }
    });
  });

  req.on('error', function (e) {
    done(
      new InternalOAuthError('Failed to fetch user profile via SOAP request', e)
    );
  });

  req.write(soapRequest);
  req.end();
};

MicrosoftStrategy.prototype.constructSoapRequest = function (accessToken) {
  return `<?xml version='1.0' encoding='utf-8'?>
       <s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'>
       <s:Header>
           <h:ApplicationToken i:nil='true' xmlns:h='https://bingads.microsoft.com/Customer/v13' xmlns:i='http://www.w3.org/2001/XMLSchema-instance' />
           <h:AuthenticationToken xmlns:h='https://bingads.microsoft.com/Customer/v13'>${accessToken}</h:AuthenticationToken>
           <h:DeveloperToken xmlns:h='https://bingads.microsoft.com/Customer/v13'>${this.developerToken}</h:DeveloperToken>
       </s:Header>
       <s:Body>
           <GetUserRequest xmlns='https://bingads.microsoft.com/Customer/v13'>
           <UserId i:nil='true' xmlns:i='http://www.w3.org/2001/XMLSchema-instance' />
           </GetUserRequest>
       </s:Body>
       </s:Envelope>`;
};

/**
 * Expose `Strategy`.
 */

module.exports = MicrosoftStrategy;
