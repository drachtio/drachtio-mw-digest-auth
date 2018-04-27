# drachtio-mw-digest-auth
[![Build Status](https://secure.travis-ci.org/davehorton/drachtio-mw-digest-auth.png)](http://travis-ci.org/davehorton/drachtio-mw-digest-auth) [![NPM version](https://badge.fury.io/js/drachtio-mw-digest-auth.svg)](http://badge.fury.io/js/drachtio-mw-digest-auth)

Performs SIP Digest-based authentication for a user agent server (UAS) or proxy built using [drachtio-srf](https://github.com/davehorton/drachtio-srf)


## Usage

Install this as drachtio middleware, providing an object that specifies the sip realm to use in challenges, and a function that provides (via callback) the password for a given username and sip realm.
```js
const Srf = require('drachtio-srf');
const srf = new Srf() ;
const digestAuth = require('drachtio-mw-digest-auth') ;

srf.connect({...}) ;

const challenge = digestAuth({
  realm: 'sip.drachtio.org',
  passwordLookup: function(username, realm, callback) {
    // ..lookup password for username in realm
    return callback(null, password) ;
  }
}) ;

srf.use( 'register', challenge) ;

srf.register((req, res) => {

  // if we reach here we have an authenticated request

  console.log(req.authorization) ;
  /*
    Digest: username="103482",realm="sip.drachtio.org",nonce="df24fd41-4fc5-416f-b163-90f774ca0358" \
      uri="sip:73.15.46.10:6060",algorithm=MD5,response="a4881ad854cc0677158206ac9fa90e3b", \
      qop=auth,nc=00000032,cnonce="ea5cec20"

    console.log =>
    {
      scheme: 'digest',
      username: '103482',
      realm: 'sip.drachtio.org',
      nonce: 'df24fd41-4fc5-416f-b163-90f774ca0358',
      uri: 'sip:72.1.46.10:6060',
      algorithm: 'MD5',
      response: 'a4881ad854cc0677158206ac9fa90e3b',
      qop: 'auth',
      nc: '00000032',
      cnonce: 'ea5cec20'
    }
   */
  } 
});
```
## Options
### 407 Proxy Authentication Required
To generate a `407 Proxy Authentication Required` challenge response instead of `401 Unauthorized` include a `proxy` property with a value `true`, e.g:

```js
const challenge = digestAuth({
  proxy: true,
  realm: 'sip.drachtio.org',
  passwordLookup: function(username, realm, callback) {
    // ..lookup password for username in realm
    return callback(null, password) ;
  }
}) ;
```
### Dynamically determining realm based on the request
Realm can be provided as a static value in the middleware configuration, but if it is necessary to dynamically determine the realm based on the specific SIP request method you can provide a function rather than a static string for the realm property.  The function takes one parameter, the sip request, and must return either a string or a Promise that resolves to a string, e.g.
```js
const challenge = digestAuth({
  realm: (req) => {
    return lookupRealm(req.uri);  // must return a promise resolving to a realm value to us
  }),
  ...
});
```
