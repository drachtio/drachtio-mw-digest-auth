const assert = require('assert');
const nonce = require('nonce')();
const {createHash} = require('crypto');
const parseUri = require('drachtio-srf').parseUri;
const debug = require('debug')('drachtio:mw-digest-auth');

function defaultRealm(req) {
  const uri = parseUri(req.uri);
  return uri.host;
}

function respondChallenge(req, res, status, realm, qop, nonceValue) {
  const headers = {} ;

  return Promise.resolve()
    .then(() => {
      if (typeof realm === 'function') return realm(req);
      return realm;
    })
    .then((theRealm) => {
      if (401 === status) {
        headers['WWW-Authenticate'] =
          `Digest realm="${theRealm}", algorithm=MD5, qop="${qop}", nonce="${nonceValue}"`;
      }
      else if (407 === status) {
        headers['Proxy-Authenticate'] =
          `Digest realm="${theRealm}", algorithm=MD5, qop="${qop}", nonce="${nonceValue}"`;
      }
      res.send(status, {headers: headers}) ;
      return;
    });
}

function digest(opts) {
  assert(typeof opts.passwordLookup === 'function',
    '\'passwordLookup\' is a required option for digest authentication and must be a function') ;

  const realm = opts.realm || defaultRealm;
  const passwordLookup = opts.passwordLookup ;
  const qop = opts.qop || 'auth' ;

  // the middleware function
  return function(req, res, next) {
    try {
      if (!req.authorization && req.has('Authorization')) {
        req.authorization = parseAuthHeader(req.get('Authorization'));
      }
      if (!req.authorization && req.has('Proxy-Authorization')) {
        req.authorization = parseAuthHeader(req.get('Proxy-Authorization'));
      }
    } catch (err) {
      debug(`Error parsing authorization (or proxy-authorization) header: ${err}`);
      req.authorization = {};
    }

    if (!req.authorization || Object.keys(req.authorization).length === 0) {
      let realmSelected = realm;
      if (typeof realm === 'function') realmSelected = realm(req);

      // invalid domain?
      if (!realmSelected) {
        return res.send(403, {
          headers: {
            'Reason': 'SIP ;cause=403 ;text="Invalid domain"'
          }
        });
      }
      const nonceValue = nonce() ;
      return respondChallenge(req, res, opts.proxy ? 407 : 401, realmSelected, qop, nonceValue) ;
    }

    const auth = req.authorization;
    passwordLookup(auth.username, auth.realm, (err, password) => {
      if (err) {
        const nonceValue = nonce() ;
        return respondChallenge(req, res, opts.proxy ? 407 : 401, realm, qop, nonceValue) ;
      }
      else if (!password) {
        debug(`Unknown user: ${auth.username}`);
        return res.send(403);
      }
      debug(`password returned: ${JSON.stringify(password)}, authorization header: ${JSON.stringify(auth)}`);

      let ha1_string;
      if (password && password.ha1) {
        ha1_string = password.ha1;
      } else {
        const ha1 = createHash('md5');
        ha1.update([auth.username, auth.realm, password].join(':'));
        ha1_string = ha1.digest('hex');
      }
      const ha2 = createHash('md5');
      ha2.update([req.method, auth.uri].join(':'));
      const response = createHash('md5');
      const responseParams = [
        ha1_string,
        auth.nonce
      ];

      if (auth.cnonce) {
        responseParams.push(auth.nc);
        responseParams.push(auth.cnonce);
      }

      if (auth.qop) {
        responseParams.push(auth.qop);
      }

      responseParams.push(ha2.digest('hex'));
      response.update(responseParams.join(':'));

      const calculated = response.digest('hex');

      if (calculated !== auth.response) {
        debug(`calculated different response: ${calculated} from that provided: ${auth.response}`);
        return res.send(403);
      }
      // success
      next() ;
    }) ;
  } ;
}

function parseAuthHeader(hdrValue) {
  const pieces = { scheme: 'digest'} ;
  ['username', 'realm', 'nonce', 'uri', 'algorithm', 'response', 'qop', 'nc', 'cnonce', 'opaque']
    .forEach((tok) => {
      const re = new RegExp(`[,\\s]{1}${tok}="?(.+?)[",]`) ;
      const arr = re.exec(hdrValue) ;
      if (arr) {
        pieces[tok] = arr[1];
        if (pieces[tok] && pieces[tok] === '"') pieces[tok] = '';
      }
    }) ;

  pieces.algorithm = pieces.algorithm || 'MD5' ;

  // this is kind of lame...nc= (or qop=) at the end fails the regex above, should figure out how to fix that
  if (!pieces.nc && /nc=/.test(hdrValue)) {
    const arr = /nc=(.*)$/.exec(hdrValue) ;
    if (arr) {
      pieces.nc = arr[1];
    }
  }
  if (!pieces.qop && /qop=/.test(hdrValue)) {
    const arr = /qop=(.*)$/.exec(hdrValue) ;
    if (arr) {
      pieces.qop = arr[1];
    }
  }

  // check mandatory fields
  ['username', 'realm', 'nonce', 'uri', 'response'].forEach((tok) => {
    if (!pieces[tok]) throw new Error(`missing authorization component: ${tok}`);
  }) ;
  debug(`parsed header: ${JSON.stringify(pieces)}`);
  return pieces ;
}

module.exports = digest ;
