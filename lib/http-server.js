'use strict';

var fs = require('fs'),
    union = require('union'),
    ecstatic = require('ecstatic'),
    auth = require('basic-auth'),
    httpProxy = require('http-proxy'),
    corser = require('corser'),
    path = require('path'),
    secureCompare = require('secure-compare');

// a hacky and direct workaround to fix https://github.com/http-party/http-server/issues/525
function getCaller() {
  try {
    var stack = new Error().stack;
    var stackLines = stack.split('\n');
    var callerStack = stackLines[3];
    return callerStack.match(/at (.+) \(/)[1];
  }
  catch (error) {
    return '';
  }
}

var _pathNormalize = path.normalize;
path.normalize = function (p) {
  var caller = getCaller();
  var result = _pathNormalize(p);
  // https://github.com/jfhbrook/node-ecstatic/blob/master/lib/ecstatic.js#L20
  if (caller === 'decodePathname') {
    result = result.replace(/\\/g, '/');
  }
  return result;
};

//
// Remark: backwards compatibility for previous
// case convention of HTTP
//
exports.HttpServer = exports.HTTPServer = HttpServer;

/**
 * Returns a new instance of HttpServer with the
 * specified `options`.
 */
exports.createServer = function (options) {
  return new HttpServer(options);
};

/**
 * Constructor function for the HttpServer object
 * which is responsible for serving static files along
 * with other HTTP-related features.
 */
function HttpServer(options) {
  options = options || {};

  if (options.root) {
    this.root = options.root;
  }
  else {
    try {
      fs.lstatSync('./public');
      this.root = './public';
    }
    catch (err) {
      this.root = './';
    }
  }

  this.headers = options.headers || {};

  this.cache = (
    options.cache === undefined ? 3600 :
    // -1 is a special case to turn off caching.
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control#Preventing_caching
    options.cache === -1 ? 'no-cache, no-store, must-revalidate' :
    options.cache // in seconds.
  );
  this.showDir = options.showDir !== 'false';
  this.autoIndex = options.autoIndex !== 'false';
  this.showDotfiles = options.showDotfiles;
  this.gzip = options.gzip === true;
  this.brotli = options.brotli === true;
  if (options.ext) {
    this.ext = options.ext === true
      ? 'html'
      : options.ext;
  }
  this.contentType = options.contentType ||
    this.ext === 'html' ? 'text/html' : 'application/octet-stream';

  var before = options.before ? options.before.slice() : [];

  if (options.logFn) {
    before.push(function (req, res) {
      options.logFn(req, res);
      res.emit('next');
    });
  }

  if (options.username || options.password) {
    before.push(function (req, res) {
      var credentials = auth(req);

      // We perform these outside the if to avoid short-circuiting and giving
      // an attacker knowledge of whether the username is correct via a timing
      // attack.
      if (credentials) {
        // if credentials is defined, name and pass are guaranteed to be string
        // type
        var usernameEqual = secureCompare(options.username.toString(), credentials.name);
        var passwordEqual = secureCompare(options.password.toString(), credentials.pass);
        if (usernameEqual && passwordEqual) {
          return res.emit('next');
        }
      }

      res.statusCode = 401;
      res.setHeader('WWW-Authenticate', 'Basic realm=""');
      res.end('Access denied');
    });
  }

  if (options.cors) {
    this.headers['Access-Control-Allow-Origin'] = '*';
    this.headers['Access-Control-Allow-Headers'] = 'Origin, X-Requested-With, Content-Type, Accept, Range';
    if (options.corsHeaders) {
      options.corsHeaders.split(/\s*,\s*/)
          .forEach(function (h) { this.headers['Access-Control-Allow-Headers'] += ', ' + h; }, this);
    }
    before.push(corser.create(options.corsHeaders ? {
      requestHeaders: this.headers['Access-Control-Allow-Headers'].split(/\s*,\s*/)
    } : null));
  }

  if (options.robots) {
    before.push(function (req, res) {
      if (req.url === '/robots.txt') {
        res.setHeader('Content-Type', 'text/plain');
        var robots = options.robots === true
          ? 'User-agent: *\nDisallow: /'
          : options.robots.replace(/\\n/, '\n');

        return res.end(robots);
      }

      res.emit('next');
    });
  }

  // Ricket's addition -- a honeypot to hopefully waste bandwidth!
  var badUrls = [
      '/webdav',
      '/w00tw00t.at.ISC.SANS.DFind:)',
      '/hndUnblock.cgi',
      '/tmUnblock.cgi',
      '/channel/100_TV.ts?uid=123',
      '/status',
      '/stat',
      '/SQlite/main.php',
      '/sqlitemanager/main.php',
      '/SQLiteManager-1.2.4/main.php',
      '/SQLite/SQLiteManager-1.2.4/main.php',
      '/sqlite/main.php',
      '/myadmin',
      '/sql',
      '/mysql',
      '/script',
      '/PMA2012/',
      '/pma2012/',
      '/PMA2011/',
      '/pma2011/',
      '/phpmyadmin2/',
      '/phpmyadmin3/',
      '/phpmyadmin4/',
      '/phpMyAdmin/scripts/setup.php',
      '/x',
      '/../../../../../../../mnt/mtd/qt',
      '/language/Swedish${IFS}&&echo${IFS}610cker>qt&&tar${IFS}/string.js',
      '/cgi/common.cgi',
      '/stssys.htm',
      '/command.php',
      '/muieblackcat',
      '//phpMyAdmin/scripts/setup.php',
      '//phpmyadmin/scripts/setup.php',
      '//pma/scripts/setup.php',
      '//myadmin/scripts/setup.php',
      '//MyAdmin/scripts/setup.php',
      '/CFIDE/administrator'
    ];
  var badUrlsWithSlash = badUrls.map(function (url) { return url + "/"; });
  before.push(function (req, res) {
    if (badUrls.indexOf(req.url) > -1
            || badUrlsWithSlash.indexOf(req.url) > -1
            || req.url.startsWith('/http') || req.url.startsWith('http')) {
      console.log('Bad url! Redirecting to 10GB download, lol');
      res.writeHead(302, {
        'Location': 'https://speed.hetzner.de/10GB.bin',
        'X-Nothing-To-See-Here': 'Move-Along'
      });
      return res.end();
    }
    res.emit('next');
  });

  before.push(ecstatic({
    root: this.root,
    cache: this.cache,
    showDir: this.showDir,
    serverHeader: false,
    showDotfiles: this.showDotfiles,
    autoIndex: this.autoIndex,
    defaultExt: this.ext,
    gzip: this.gzip,
    brotli: this.brotli,
    contentType: this.contentType,
    handleError: typeof options.proxy !== 'string'
  }));

  if (typeof options.proxy === 'string') {
    var proxy = httpProxy.createProxyServer({});
    before.push(function (req, res) {
      proxy.web(req, res, {
        target: options.proxy,
        changeOrigin: true
      }, function (err, req, res, target) {
        if (options.logFn) {
          options.logFn(req, res, {
            message: err.message,
            status: res.statusCode });
        }
        res.emit('next');
      });
    });
  }

  var serverOptions = {
    before: before,
    headers: this.headers,
    onError: function (err, req, res) {
      if (options.logFn) {
        options.logFn(req, res, err);
      }

      res.end();
    }
  };

  if (options.https) {
    serverOptions.https = options.https;
  }

  this.server = union.createServer(serverOptions);
  if (options.timeout !== undefined) {
    this.server.setTimeout(options.timeout);
  }
}

HttpServer.prototype.listen = function () {
  this.server.listen.apply(this.server, arguments);
};

HttpServer.prototype.close = function () {
  return this.server.close();
};
