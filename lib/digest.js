const assert = require('assert');
const nonce = require('nonce')();
const {createHash} = require('crypto');
const debug = require('debug')('drachtio:mw-digest-auth');

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
  assert(typeof opts.realm === 'string' || typeof opts.realm === 'function',
    '\'realm\' is a required option for digest authentication') ;
  assert(typeof opts.passwordLookup === 'function',
    '\'passwordLookup\' is a required option for digest authentication and must be a function') ;

  const realm = opts.realm ;
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
      const nonceValue = nonce() ;
      return respondChallenge(req, res, opts.proxy ? 407 : 401, realm, qop, nonceValue) ;
    }

    const auth = req.authorization;
    passwordLookup(auth.username, auth.realm, (err, password) => {
      if (err) {
        console.error(`digest: Error calling passwordLookup: ${err}`);
        const nonceValue = nonce() ;
        return respondChallenge(req, res, opts.proxy ? 407 : 401, realm, qop, nonceValue) ;
      }
      debug(`password returned: ${password}, authorization header: ${JSON.stringify(auth)}`);

      const ha1 = createHash('md5');
      ha1.update([auth.username, auth.realm, password].join(':'));
      const ha2 = createHash('md5');
      ha2.update([req.method, auth.uri].join(':'));
      const response = createHash('md5');
      const responseParams = [
        ha1.digest('hex'),
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

  // check mandatory fields
  ['username', 'realm', 'nonce', 'uri', 'response'].forEach((tok) => {
    if (!pieces[tok]) throw new Error(`missing authorization component: ${tok}`);
  }) ;
  debug(`parsed header: ${JSON.stringify(pieces)}`);
  return pieces ;
}

module.exports = digest ;
