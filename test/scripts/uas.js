const Emitter = require('events');
const Srf = require('drachtio-srf');
const digestAuth = require('../..');
const config = require('config');
const debug = require('debug')('drachtio:test');

class App extends Emitter {
  constructor() {
    super();

    this.srf = new Srf() ;
  }

  auth(method, user, password, domain, proxy) {
    this.srf.use(digestAuth({
      proxy: proxy,
      realm: domain,
      passwordLookup: (username, realm, callback) => {
        if (user !== username) return callback(null, null);
        else callback(null, password) ;
      }
    })) ;

    this.srf[method]((req, res) => {
      // if we got here then authentication succeeded
      debug(`${method} successfully authenticated`);
      res.send('invite' === method ? 480 : 200);
    });

    return new Promise((resolve, reject) => {
      this.srf.connect(config.get('drachtio'));
      this.srf.on('connect', () => {
        debug('connected');
        resolve();
      });
    });
  }

  authInvite(...args) {
    return this.auth('invite', ...args);
  }

  authRegister(...args) {
    return this.auth('register', ...args);
  }

  authSubscribe(...args) {
    return this.auth('subscribe', ...args);
  }

  disconnect() {
    debug('disconnecting from drachtio');
    this.srf.disconnect();
    return this;
  }
}

module.exports = App;
