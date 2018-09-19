# NodeBB OAuth SSO

NodeBB Plugin that allows users to login/register via any OAuth provider. This is a complete plugin.

## How to setup

1. Set environment variables:
    * `NODEBB_SSO_TYPE`: `oauth` or `oauth2`
    * `NODEBB_SSO_NAME`: your provider name in lowercase
    * `NODEBB_SSO_USER_ROUTE`: your SSO provider "user profile" API endpoint
    * (optional) `NODEBB_SSO_CALLBACK_URL`, by default: */auth/`NODEBB_SSO_NAME`/callback*
    * (optional) `NODEBB_SSO_SCOPE`: comma separated list, by default: *profile*
    * (optional) `NODEBB_SSO_ICON`: Font Awesome icon name, by default: *fa-check-square*
    * (optional) `NODEBB_SSO_SKIP_GDPR`: Set *true* to skip GDPR banner, by default: *false*
    * OAuth:
      * `NODEBB_OAUTH_REQUEST_TOKEN_URL`
      * `NODEBB_OAUTH_ACCESS_TOKEN_URL`
      * `NODEBB_OAUTH_USER_AUTHORIZATION_URL`
      * `NODEBB_OAUTH_CONSUMER_KEY`
      * `NODEBB_OAUTH_CONSUMER_SECRET`
    * OAuth2:
      * `NODEBB_OAUTH2_AUTHORIZATION_URL`
      * `NODEBB_OAUTH2_TOKEN_URL`
      * `NODEBB_OAUTH2_CLIENT_ID`
      * `NODEBB_OAUTH2_CLIENT_SECRET`
1. Activate this plugin from the plugins page
1. Restart your NodeBB
1. Let NodeBB take care of the rest

## Trouble?

Find us on [the community forums](http://community.nodebb.org)!
