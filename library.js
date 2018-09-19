(function(module) {
	"use strict";

	/*
		Welcome to the SSO OAuth plugin! If you're inspecting this code, you're probably looking to
		hook up NodeBB with your existing OAuth endpoint.

		Step 1: Fill in the "constants" section below with the requisite informaton. Either the "oauth"
				or "oauth2" section needs to be filled, depending on what you set "type" to.

		Step 2: Give it a whirl. If you see the congrats message, you're doing well so far!

		Step 3: Customise the `parseUserReturn` method to normalise your user route's data return into
				a format accepted by NodeBB. Instructions are provided there. (Line 146)

		Step 4: If all goes well, you'll be able to login/register via your OAuth endpoint credentials.
	*/

	var User = module.parent.require('./user'),
		Groups = module.parent.require('./groups'),
		meta = module.parent.require('./meta'),
		db = module.parent.require('../src/database'),
		passport = module.parent.require('passport'),
		fs = module.parent.require('fs'),
		path = module.parent.require('path'),
		nconf = module.parent.require('nconf'),
		winston = module.parent.require('winston'),
		async = module.parent.require('async'),
	  env = module.parent.require('process').env;

	var authenticationController = module.parent.require('./controllers/authentication');

	/**
	 * REMEMBER
	 *   Never save your OAuth Key/Secret or OAuth2 ID/Secret pair in code! It could be published and leaked accidentally.
	 *   Save it into your config.json file instead:
	 *
	 *   {
	 *     ...
	 *     "oauth": {
	 *       "id": "someoauthid",
	 *       "secret": "youroauthsecret"
	 *     }
	 *     ...
	 *   }
	 *
	 *   ... or use environment variables instead:
	 *
	 *   `OAUTH__ID=someoauthid OAUTH__SECRET=youroauthsecret node app.js`
	 */

	var constants = Object.freeze({
			type: env.NODEBB_SSO_TYPE || '',	// Either 'oauth' or 'oauth2'
			name: env.NODEBB_SSO_NAME || '',	// Something unique to your OAuth provider in lowercase, like "github", or "nodebb"
			oauth: {
				requestTokenURL: env.NODEBB_OAUTH_REQUEST_TOKEN_URL || '',
				accessTokenURL: env.NODEBB_OAUTH_ACCESS_TOKEN_URL || '',
				userAuthorizationURL: env.NODEBB_OAUTH_USER_AUTHORIZATION_URL || '',
				consumerKey: env.NODEBB_OAUTH_CONSUMER_KEY || nconf.get('oauth:key'),	// don't change this line
				consumerSecret: env.NODEBB_OAUTH_CONSUMER_SECRET || nconf.get('oauth:secret'),	// don't change this line
			},
			oauth2: {
				authorizationURL: env.NODEBB_OAUTH2_AUTHORIZATION_URL || '',
				tokenURL: env.NODEBB_OAUTH2_TOKEN_URL || '',
				clientID: env.NODEBB_OAUTH2_CLIENT_ID || nconf.get('oauth:id'),	// don't change this line
				clientSecret: env.NODEBB_OAUTH2_CLIENT_SECRET || nconf.get('oauth:secret'),	// don't change this line
			},
			userRoute: env.NODEBB_SSO_USER_ROUTE || '',	// This is the address to your app's "user profile" API endpoint (expects JSON)
      callbackURL: env.NODEBB_SSO_CALLBACK_URL || '/auth/' + env.NODEBB_SSO_NAME + '/callback',
      scope: env.NODEBB_SSO_SCOPE || 'profile',
      icon: env.NODEBB_SSO_ICON || 'fa-check-square',
      // TODO: Fix not working option, now it is forced set to true in code. Maybe problem with value `true`.
      skip_gdpr: env.NODEBB_SSO_SKIP_GDPR === 'true'
		}),
		configOk = false,
		OAuth = {}, passportOAuth, opts;

	if (!constants.name) {
		winston.error('[sso-oauth] Please specify a name for your OAuth provider, use env NODEBB_SSO_NAME', );
	} else if (!constants.type || (constants.type !== 'oauth' && constants.type !== 'oauth2')) {
		winston.error('[sso-oauth] Please specify an OAuth strategy to utilise, use env NODEBB_SSO_TYPE');
	} else if (!constants.userRoute) {
		winston.error('[sso-oauth] User Route required, use env NODEBB_SSO_USER_ROUTE');
	} else {
		configOk = true;
	}

	OAuth.getStrategy = function(strategies, callback) {
		if (configOk) {
			passportOAuth = require('passport-oauth')[constants.type === 'oauth' ? 'OAuthStrategy' : 'OAuth2Strategy'];

			if (constants.type === 'oauth') {
				// OAuth options
				opts = constants.oauth;
				opts.callbackURL = nconf.get('url') + constants.callbackURL;

				passportOAuth.Strategy.prototype.userProfile = function(token, secret, params, done) {
					this._oauth.get(constants.userRoute, token, secret, function(err, body, res) {
						if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

						try {
							var json = JSON.parse(body);
							OAuth.parseUserReturn(json, function(err, profile) {
								if (err) return done(err);
								profile.provider = constants.name;

								done(null, profile);
							});
						} catch(e) {
							done(e);
						}
					});
				};
			} else if (constants.type === 'oauth2') {
				// OAuth 2 options
				opts = constants.oauth2;
				opts.callbackURL = nconf.get('url') + constants.callbackURL;

				passportOAuth.Strategy.prototype.userProfile = function(accessToken, done) {
					this._oauth2.get(constants.userRoute, accessToken, function(err, body, res) {
						if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

						try {
							var json = JSON.parse(body);
							OAuth.parseUserReturn(json, function(err, profile) {
								if (err) return done(err);
								profile.provider = constants.name;

								done(null, profile);
							});
						} catch(e) {
							done(e);
						}
					});
				};
			}

			opts.passReqToCallback = true;

			passport.use(constants.name, new passportOAuth(opts, function(req, token, secret, profile, done) {
			  var payload = Object.assign({}, profile, {
          oAuthid: profile.id,
          handle: profile.displayName,
          email: profile.emails[0].value,
          isAdmin: profile.isAdmin
        });
				OAuth.login(payload, function(err, user) {
					if (err) {
						return done(err);
					}

					authenticationController.onSuccessfulLogin(req, user.uid);
					done(null, user);
				});
			}));

			strategies.push({
				name: constants.name,
				url: '/auth/' + constants.name,
				callbackURL: constants.callbackURL,
				icon: constants.icon,
				scope: (constants.scope || '').split(',')
			});

			callback(null, strategies);
		} else {
			callback(new Error('OAuth Configuration is invalid'));
		}
	};

	OAuth.parseUserReturn = function(data, callback) {
		// Alter this section to include whatever data is necessary
		// NodeBB *requires* the following: id, displayName, emails.
		// Everything else is optional.

		// Find out what is available by uncommenting this line:
		// console.log(data);

		var profile = data;
		profile.id = data.sub;
		profile.displayName = data.preferred_username;
		profile.emails = [{ value: data.email }];

		// Do you want to automatically make somebody an admin? This line might help you do that...
		profile.isAdmin = typeof data.roles !== 'undefined'
      ? Array.isArray(data.roles) && data.roles.indexOf('admin') > -1
      : false;

		// Delete or comment out the next TWO (2) lines when you are ready to proceed
		// process.stdout.write('===\nAt this point, you\'ll need to customise the above section to id, displayName, and emails into the "profile" object.\n===');
		// return callback(new Error('Congrats! So far so good -- please see server log for details'));

		callback(null, profile);
	}

	OAuth.login = function(payload, callback) {
		OAuth.getUidByOAuthid(payload.oAuthid, function(err, uid) {
			if(err) {
				return callback(err);
			}

			if (uid !== null) {
				// Existing User
				callback(null, {
					uid: uid
				});
			} else {
				// New User
				var success = function(uid) {
					// Save provider-specific information to the user
					User.setUserField(uid, constants.name + 'Id', payload.oAuthid);
					db.setObjectField(constants.name + 'Id:uid', payload.oAuthid, uid);

					if (payload.isAdmin) {
						Groups.join('administrators', uid, function(err) {
							callback(null, {
								uid: uid
							});
						});
					} else {
						callback(null, {
							uid: uid
						});
					}
				};

				User.getUidByEmail(payload.email, function(err, uid) {
					if(err) {
						return callback(err);
					}

					if (!uid) {
						User.create({
							username: payload.handle,
							email: payload.email,
              // Force GDPR consent true, skip the GDPR banner on login via OAuth 2.0
              gdpr_consent: true,
						}, function(err, uid) {
							if(err) {
								return callback(err);
							}

							success(uid);
						});
					} else {
						success(uid); // Existing account -- merge
					}
				});
			}
		});
	};

	OAuth.getUidByOAuthid = function(oAuthid, callback) {
		db.getObjectField(constants.name + 'Id:uid', oAuthid, function(err, uid) {
			if (err) {
				return callback(err);
			}
			callback(null, uid);
		});
	};

	OAuth.deleteUserData = function(data, callback) {
		async.waterfall([
			async.apply(User.getUserField, data.uid, constants.name + 'Id'),
			function(oAuthIdToDelete, next) {
				db.deleteObjectField(constants.name + 'Id:uid', oAuthIdToDelete, next);
			}
		], function(err) {
			if (err) {
				winston.error('[sso-oauth] Could not remove OAuthId data for uid ' + data.uid + '. Error: ' + err);
				return callback(err);
			}

			callback(null, data);
		});
	};

	module.exports = OAuth;
}(module));
