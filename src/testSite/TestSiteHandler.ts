// Module containing web site logic for the test site.
//
// Site design notes
//
// Browser session cookies have been enabled for tracking the user
// session once logged in. The back-end database is an in-memory NeDB
// (https://github.com/louischatriot/nedb/) instance. The user
// profile schema information is in UserDBRecord.
//
// URI space:
//   / : Home page, hosted from index.ejs (template). If not logged in, redirects to /login
//   /login : GET for login page (login.ejs)
//   /sqrl : GET/POST API endpoint for SQRL API

import * as bodyParser from 'body-parser';
import * as cookieParser from 'cookie-parser';
import * as ejs from 'ejs';
import * as express from 'express';
import * as expressLayouts from 'express-ejs-layouts';
import * as expressSession from 'express-session';
import * as fs from 'fs';
import * as helmet from 'helmet';
import * as http from 'http';
import * as neDB from 'nedb';
import * as os from 'os';
import * as passport from 'passport';
import * as path from 'path';
import * as qr from 'qr-image';
import * as favicon from 'serve-favicon';
import * as spdy from 'spdy';
import { promisify } from 'util';
import { AuthCompletionInfo, ClientRequestInfo, ILogger, ISQRLIdentityStorage, NutInfo, SQRLExpress, SQRLStrategy, SQRLStrategyConfig, TIFFlags, UrlAndNut } from '../passport-sqrl';

// TypeScript definitions for SPDY do not include an overload that allows the common
// Express app pattern as a param. Inject an overload to avoid compilation errors.
declare module 'spdy' {
  namespace server {
    export function create(options: ServerOptions, handler: express.Application): Server;
  }
}

// TypeScript definitions for http do not include an overload that allows the common
// Express app pattern as a param. Inject an overload to avoid compilation errors.
declare module 'http' {
  export function createServer(handler: express.Application): Server;
}

// Promisify extensions.
declare module 'nedb' {
  class Nedb {
    public findOneAsync(query: any): Promise<any>;
    public insertAsync(newDoc: any): Promise<any>;
    public updateAsync(query: any, updateQuery: any, options?: Nedb.UpdateOptions): Promise<number>;
  }
}
(<any> neDB).prototype.findOneAsync = promisify(neDB.prototype.findOne);
(<any> neDB).prototype.insertAsync = promisify(neDB.prototype.insert);
(<any> neDB).prototype.updateAsync = promisify(neDB.prototype.update);

const serverTlsCertDir = __dirname;
const serverTlsKey = serverTlsCertDir + "/TestSite.PrivateKey.pem";

// Root cert must be trusted on devices, but the server should serve its leaf and intermediate.
// Particularly important for Android where the "Settings->Security->Install From SD Card"
// only allows installing a root cert into the user trusted store. 
const serverTlsCert = serverTlsCertDir + "/TestSite.LeafAndIntermediate.Cert.pem";

const oneDayInSeconds = 24 * 3600;

export class TestSiteHandler implements ISQRLIdentityStorage {
  private testSiteServer: spdy.Server;
  private httpCertServer: http.Server;
  private sqrlPassportStrategy: SQRLStrategy;
  private sqrlApiHandler: SQRLExpress;
  private userTable: neDB;
  private nutTable: neDB;
  private log: ILogger;

  constructor(log: ILogger, port: number = 5858, domainName: string | null = null) {
    this.log = log;
    let webSiteDir = path.join(__dirname, 'WebSite');
    const sqrlApiRoute = '/sqrl';
    const loginPageRoute = '/login';
    const pollNutRoute = '/pollNut/:nut';
    const loginSuccessRedirect = '/';

    this.userTable = new neDB(<neDB.DataStoreOptions> { inMemoryOnly: true });
    this.nutTable = new neDB(<neDB.DataStoreOptions> { inMemoryOnly: true });

    let sqrlConfig = <SQRLStrategyConfig> {
      localDomainName: domainName || this.getLocalIPAddresses()[0],
      port: port,
      urlPath: sqrlApiRoute,
    };

    // The SQRL API needs its own dedicated API endpoint. SQRLExpress
    // handles this API for us.
    this.sqrlApiHandler = new SQRLExpress(this, this.log, sqrlConfig);

    // Configure PassportJS with the SQRL Strategy. PassportJS will add the
    // implicit res.login() method used later on. We use the user's SQRL primary
    // public key as the key for the user profile in back-end database storage.
    this.sqrlPassportStrategy = new SQRLStrategy(this.log, sqrlConfig);
    passport.use(this.sqrlPassportStrategy);
    passport.serializeUser((user: Express.User, done) => done(undefined, (<UserDBRecord> user).sqrlPrimaryIdentityPublicKey));
    passport.deserializeUser((id: any, done: (err: Error | null, doc: any) => void) => this.findUser(id, done));

    // Useful: http://toon.io/understanding-passportjs-authentication-flow/
    const app = express()
      // ----------------------------------------------------------------------
      // Layout and default parsers
      // ----------------------------------------------------------------------
      .set('view engine', 'ejs')
      .set('views', path.join(__dirname, 'views'))
      .use(expressLayouts)
      .use(favicon(webSiteDir + '/favicon.ico'))  // Early to handle quickly without passing through other middleware layers
      .use(cookieParser())
      .use(bodyParser.urlencoded({extended: true}))  // Needed for parsing bodies (login)

      // ----------------------------------------------------------------------
      // Content security policy header configuration
      // https://helmetjs.github.io/docs/csp/
      // ----------------------------------------------------------------------
      .use(helmet.contentSecurityPolicy(<helmet.IHelmetContentSecurityPolicyConfiguration> {
        directives: {
          defaultSrc: [ "'self'" ],
          scriptSrc: [ "'self'", 'code.jquery.com' ]
        }
      }))

      // ----------------------------------------------------------------------
      // Other security headers
      // ----------------------------------------------------------------------
      .use(helmet.frameguard(<helmet.IHelmetFrameguardConfiguration> { action: 'deny' }))  // Disallow IFRAME embeds
      // Disabling HSTS header locally but restore if using this code in a real site:
      // .use(helmet.hsts(<helmet.IHelmetHstsConfiguration> { maxAge: oneDayInSeconds }))

      // ----------------------------------------------------------------------
      // Session: We use sessions for ambient cookie-based login.
      // NOTE: If you're copying this for use in your own site, you need to
      // replace the secret below with a secret deployed securely.
      // ----------------------------------------------------------------------
      .use(expressSession({  // Session load+decrypt support, must come before passport.session
        secret: 'SQRL-Test',  // SECURITY: If reusing site code, you need to supply this secret from a real secret store.
        resave: true,
        saveUninitialized: true
      }))
      .use(passport.initialize())
      .use(passport.session())

      // ----------------------------------------------------------------------
      // The /login route displays a SQRL QR code.
      // ----------------------------------------------------------------------
      .get(loginPageRoute, (req, res) => {
        this.log.debug('/login requested');
        let urlAndNut: UrlAndNut = this.sqrlApiHandler.getSqrlUrl(req);
        this.nutIssuedToClientAsync(urlAndNut)
          .then(() => {
            let qrSvg = qr.imageSync(urlAndNut.url, { type: 'svg', parse_url: true });
            res.render('login', {
              subpageName: 'Log In',
              sqrlUrl: urlAndNut.url,
              sqrlNut: urlAndNut.nutString,
              sqrlQR: qrSvg
            });
          });
      })

      // ----------------------------------------------------------------------
      // The SQRL API and login sequence does not use the HTTP Authenticate
      // header, but instead acts as a distinct API surface area. We use a
      // dedicated route just for handing its API calls, and use back-end
      // storage mechanisms to complete the login on the user's behalf.
      // ----------------------------------------------------------------------
      .post(sqrlApiRoute, this.sqrlApiHandler.handleSqrlApi)
      
      // ----------------------------------------------------------------------
      // Used by login.ejs
      // ----------------------------------------------------------------------
      .get(pollNutRoute, (req, res) => {
        if (req.params.nut) {
          this.getNutRecordAsync(req.params.nut)
            .then(nutRecord => {
              if (!nutRecord) {
                this.log.debug(`pollNut: ${req.params.nut}: No nut record, returning 404`);
                res.statusCode = 404;
                res.end();
              } else if (!nutRecord.loggedIn || !nutRecord.clientPrimaryIdentityPublicKey) {
                this.log.finest(() => `pollNut: ${req.params.nut}: Nut not logged in`);
                res.send(<NutPollResult> { loggedIn: false });
              } else {
                this.findUser(nutRecord.clientPrimaryIdentityPublicKey, (err: Error | null, userDBRecord: UserDBRecord | null) => {
                  if (err) {
                    this.log.debug(`pollNut: ${req.params.nut}: Error finding user: ${err}`);
                    res.statusCode = 500;
                    res.send(err.toString());
                  } else {
                    this.log.debug(`pollNut: ${req.params.nut}: Nut logged in, logging user in via PassportJS`);
                    // Ensure the cookie header for the response is set the way Passport normally does it.
                    req.login(<UserDBRecord> userDBRecord, loginErr => {
                      if (loginErr) {
                        this.log.debug(`pollNut: ${req.params.nut}: PassportJS login failed: ${loginErr}`);
                        res.statusCode = 400;
                        res.send(loginErr.toString());
                      } else {
                        res.send(<NutPollResult> {
                          loggedIn: nutRecord.loggedIn,
                          redirectTo: loginSuccessRedirect
                        });
                      }
                    });
                  }
                });
              }
            })
            .catch(reason => {
              res.statusCode = 400;
              res.send(reason);
            });
        } else {
          res.statusCode = 404;
          res.end();
        }
      })

      // ----------------------------------------------------------------------
      // Main page. Redirects to /login if there is no logged-in user
      // via the client cookie. Otherwise, relies on the implicit PassportJS
      // user record lookup configured above.
      // ----------------------------------------------------------------------
      .get('/', (req, res) => {
        this.log.debug('/ requested');
        if (!req.user) {
          res.redirect(loginPageRoute);
        } else {
          res.render('index', {
            subpageName: 'Main',
            username: (<UserDBRecord> req.user).name,
            sqrlPublicKey: (<UserDBRecord> req.user).sqrlPrimaryIdentityPublicKey
          });
        }
      })

      // ----------------------------------------------------------------------
      // Serve static scripts and assets. Must come after non-file
      // (e.g. templates, REST) middleware.
      // ----------------------------------------------------------------------
      .use(express.static(webSiteDir));

    // SQRL requires HTTPS so we use SPDY which happily gives us HTTP/2 at the same time.
    // Node 8.6+ contains a native HTTP/2 module we can move to once it moves to Stable.
    this.testSiteServer = spdy.server.create(<spdy.server.ServerOptions> {
      // Leaf cert PEM files for server certificate. See CreateLeaf.cmd and related scripts.
      cert: fs.readFileSync(serverTlsCert),
      key: fs.readFileSync(serverTlsKey),

      // SPDY-specific options
      spdy: {
        plain: false,
        connection: {
          windowSize: 1024 * 1024,
        },
        protocols: ['h2', 'http/1.1'],
      },
    }, app);
    log.info(`Test server listening on ${sqrlConfig.localDomainName}:${port}`);
    this.testSiteServer.listen(port, sqrlConfig.localDomainName);

    // Fun hack: Since we're using a custom CA cert chain, it's hard to get the root
    // cert into the trusted store especially on phones. We expose a tiny http single page
    // with links to the root cert for installation, and a link to the https site.
    const httpApp = express()
      .set('view engine', 'ejs')
      .set('views', path.join(__dirname, 'views'))
      .use(expressLayouts)
      .use(favicon(webSiteDir + '/favicon.ico'))
      .get('/certs', (req, res) => res.render('httpCerts', {
        subpageName: 'HTTPS Certs',
        httpsHost: sqrlConfig.localDomainName,
        httpsPort: port
      }))
      .get('/RootCert.Cert.pem', (req, res) => res.download(__dirname + '/RootCert.Cert.pem'))
      .get('/RootCert.Cert.cer', (req, res) => res.download(__dirname + '/RootCert.Cert.cer'))
      .get('*', (req, res) => {
        // Redirect HTTP->HTTPS except for /certs and certificate routes above.
        // NOTE: Not using https://github.com/hengkiardo/express-enforces-ssl
        // because it does not handle non-standard ports.
        let redirUrl = "https://" + (req.headers.host || "").replace((port + 1).toString(), port.toString()) + req.url;
        log.debug(`HTTP->HTTPS redir to ${redirUrl}`);
        res.writeHead(302, { Location: redirUrl });
        res.end();
      });
    this.httpCertServer = http.createServer(httpApp);
    this.httpCertServer.listen(port + 1, sqrlConfig.localDomainName);
  }

  public close(): void {
    this.testSiteServer.close();
    if (this.httpCertServer) {
      this.httpCertServer.close();
    }
  }

  // See doc comments on ISQRLIdentityStorage.nutIssuedToClientAsync().
  public async nutIssuedToClientAsync(urlAndNut: UrlAndNut, originalLoginNut?: string): Promise<void> {
    this.log.finest(() => `nutIssuedToClientAsync: Storing nut ${urlAndNut.nutString}`);
    await (<any> this.nutTable).insertAsync(new NutDBRecord(urlAndNut.nutString, urlAndNut.url, originalLoginNut));
    this.log.finest(() => `nutIssuedToClientAsync: Stored nut ${urlAndNut.nutString}`);
  }

  public async getNutInfoAsync(nut: string): Promise<NutInfo | null> {
    this.log.finest(() => `getNutInfoAsync: Retrieving nut ${nut}`);
    let nutDBRecord = await this.getNutRecordAsync(nut);  // NutDBRecord derives from NutInfo.
    if (!nutDBRecord) {
      this.log.finest(() => `getNutInfoAsync: Nut ${nut} not found`);
    } else {
      this.log.finest(() => `getNutInfoAsync: Nut ${nut} found`);
    }
    return nutDBRecord;
  }

  public async queryAsync(clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> {
    // SQRL query. We don't create any new user records, just return whether we know about the user.
    let authInfo: AuthCompletionInfo = await this.findUserByEitherKeyAsync(clientRequestInfo);
    if (authInfo.user && clientRequestInfo.returnSessionUnlockKey) {
      let user = <UserDBRecord> authInfo.user;
      authInfo.sessionUnlockKey = user.sqrlServerUnlockPublicKey;
    }
    return authInfo;
  }

  public async identAsync(clientRequestInfo: ClientRequestInfo, nutInfo: NutInfo): Promise<AuthCompletionInfo> {
    // SQRL login request.
    let authInfo: AuthCompletionInfo = await this.findUserByEitherKeyAsync(clientRequestInfo);
    if (authInfo.user) {
      // tslint:disable-next-line:no-bitwise
      if (authInfo.tifValues & TIFFlags.PreviousIDMatch) {
        // The user has specified a new primary key, rearrange the record and update.
        let user = authInfo.user;
        if (!user.sqrlPreviousIdentityPublicKeys) {
          user.sqrlPreviousIdentityPublicKeys = [];
        }
        user.sqrlPreviousIdentityPublicKeys.push(clientRequestInfo.previousIdentityPublicKey);  // TODO: Dedup
        user.sqrlPrimaryIdentityPublicKey = clientRequestInfo.primaryIdentityPublicKey;
        let searchRecord = <UserDBRecord> {
          sqrlPrimaryIdentityPublicKey: clientRequestInfo.previousIdentityPublicKey
        };
        authInfo.user = await (<any> this.userTable).updateAsync(searchRecord, user);
      }
    } else {
      // Didn't already exist, create an initial version.
      let newRecord = UserDBRecord.newFromClientRequestInfo(clientRequestInfo);
      let result: UserDBRecord = await (<any> this.userTable).insertAsync(newRecord);
      authInfo.user = result;
      authInfo.tifValues = 0;
    }

    // Update the nut record for the original SQRL URL, which may be getting polled by the /pollNut
    // route right now, with a reference to the user record.
    let originalNutRecord: NutDBRecord | null = <NutDBRecord> nutInfo;  // Full info was returned from our query
    if (originalNutRecord.originalLoginNut) {
      // We have a later nut record, find the original.
      originalNutRecord = await this.getNutRecordAsync(originalNutRecord.originalLoginNut);
    }
    if (originalNutRecord) {  // May have become null when trying to find the original if it was timed out from storage
      originalNutRecord.loggedIn = true;
      originalNutRecord.clientPrimaryIdentityPublicKey = (<UserDBRecord> authInfo.user).sqrlPrimaryIdentityPublicKey;
      await (<any> this.nutTable).updateAsync({ nut: originalNutRecord.nut }, originalNutRecord);
    }
    return authInfo;
  }

  public disableAsync(clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> {
    // SQRL identity disable request.
    return Promise.resolve(new AuthCompletionInfo());  // TODO
  }

  public enableAsync(clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> {
    // SQRL identity enable request.
    return Promise.resolve(new AuthCompletionInfo());  // TODO
  }

  public removeAsync(clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> {
    // SQRL identity remove request.
    return Promise.resolve(new AuthCompletionInfo());  // TODO
  }

  private async getNutRecordAsync(nut: string): Promise<NutDBRecord | null> {
    let searchRecord = { nut: nut };
    let nutRecord: NutDBRecord | null = await (<any> this.nutTable).findOneAsync(searchRecord);
    return nutRecord;
  }

  private findUser(sqrlPublicKey: string, done: (err: Error | null, doc: any) => void): void {
    // Treat the SQRL client's public key as a primary search key in the database.
    let userDBRecord = <UserDBRecord> {
      sqrlPrimaryIdentityPublicKey: sqrlPublicKey,
    };
    this.userTable.findOne(userDBRecord, done);
  }

  private async findUserByEitherKeyAsync(clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> {
    let result = new AuthCompletionInfo();

    // Search for both keys simultaneously if the previous key is specified.
    let keyMatches = [
      { sqrlPrimaryIdentityPublicKey: clientRequestInfo.primaryIdentityPublicKey }
    ];
    if (clientRequestInfo.previousIdentityPublicKey) {
      keyMatches.push({ sqrlPrimaryIdentityPublicKey: clientRequestInfo.previousIdentityPublicKey });
    }
    let searchRecord = { $or: keyMatches };

    let doc: UserDBRecord = await (<any> this.userTable).findOneAsync(searchRecord);
    if (doc != null) {
      result.user = doc;
      if (doc.sqrlPrimaryIdentityPublicKey === clientRequestInfo.primaryIdentityPublicKey) {
        // tslint:disable-next-line:no-bitwise
        result.tifValues |= TIFFlags.CurrentIDMatch;
      } else {
        // tslint:disable-next-line:no-bitwise
        result.tifValues |= TIFFlags.PreviousIDMatch;
      }
    }
    return result;
  }

  private async findAndUpdateOrCreateUserAsync(clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> {
    // Treat the SQRL client's public key as a primary search key in the database.
    let searchRecord = <UserDBRecord> {
      sqrlPrimaryIdentityPublicKey: clientRequestInfo.primaryIdentityPublicKey,
    };
    let result = await (<any> this.userTable).findOneAsync(searchRecord);
    if (result == null) {
      // Not found by primary key. Maybe this is an identity change situation.
      // If a previous key was provided, search again.
      if (clientRequestInfo.previousIdentityPublicKey) {
        searchRecord.sqrlPrimaryIdentityPublicKey = clientRequestInfo.previousIdentityPublicKey;
        let prevKeyDoc: UserDBRecord = await (<any> this.userTable).findOneAsync(searchRecord);
        if (prevKeyDoc == null) {
          // Didn't already exist, create an initial version if this is a login API request.
          if (clientRequestInfo.sqrlCommand === 'ident') {
            let newRecord = UserDBRecord.newFromClientRequestInfo(clientRequestInfo);
            result = await (<any> this.userTable).insertAsync(newRecord);
          }
        } else {
          // The user has specified a new primary key, rearrange the record and update.
          if (!prevKeyDoc.sqrlPreviousIdentityPublicKeys) {
            prevKeyDoc.sqrlPreviousIdentityPublicKeys = [];
          }
          prevKeyDoc.sqrlPreviousIdentityPublicKeys.push(clientRequestInfo.previousIdentityPublicKey);
          prevKeyDoc.sqrlPrimaryIdentityPublicKey = clientRequestInfo.primaryIdentityPublicKey;
          await (<any> this.userTable).updateAsync(searchRecord, prevKeyDoc);
          result = prevKeyDoc;
        }
      }
    }
    let authInfo = new AuthCompletionInfo();
    authInfo.user = result;
    return authInfo;
  }

  private getLocalIPAddresses(): string[] {
    let interfaces = os.networkInterfaces();
    let addresses: string[] = [];
    // tslint:disable-next-line:forin
    for (let k in interfaces) {
      // tslint:disable-next-line:forin
      for (let k2 in interfaces[k]) {
        let address = interfaces[k][k2];
        if (address.family === 'IPv4' && !address.internal) {
          addresses.push(address.address);
        }
      }
    }
    return addresses;
  }
}

/**
 * A class modeling a user document in the database.
 * Mostly copies of ClientRequestInfo scalar fields.
 * If we're using something like MongoDB or, in our case, NeDB, we could
 * place these fields under a sub-object called, perhaps, 'sqrl',
 * we instead model the fields as a mostly-flat array of scalars
 * (except the sqrlPreviousIdentityPublicKeys which could be
 * denormalized into 4 individual fields and managed as a 4-entry array),
 * using the 'sqrl' prefix to differentiate from any other user fields
 * for the app.
 */
class UserDBRecord implements Express.User {
  public static newFromClientRequestInfo(clientRequestInfo: ClientRequestInfo): UserDBRecord {
    let result = <UserDBRecord> {
      sqrlPrimaryIdentityPublicKey: clientRequestInfo.primaryIdentityPublicKey,
      sqrlPreviousIdentityPublicKeys: [],
      sqrlServerUnlockPublicKey: clientRequestInfo.serverUnlockPublicKey,
      sqrlServerVerifyUnlockPublicKey: clientRequestInfo.serverVerifyUnlockPublicKey,
      sqrlUseSqrlIdentityOnly: clientRequestInfo.useSqrlIdentityOnly,
      sqrlHardLockSqrlUse: clientRequestInfo.hardLockSqrlUse
    };

    if (clientRequestInfo.previousIdentityPublicKey) {
      result.sqrlPreviousIdentityPublicKeys.push(clientRequestInfo.previousIdentityPublicKey);
    }

    return result;
  }

  // _id is implicit from NeDB.
  // tslint:disable-next-line
  public _id?: string;
  
  /** User name. Could be filled in from any login form submitted from the client. */
  public name?: string;

  /**
   * The current primary identity key. This is a primary search term and would
   * make sense to place into a database index.
   */
  public sqrlPrimaryIdentityPublicKey?: string;

  /** Up to four previously seen previous identity keys, for reference. */
  public sqrlPreviousIdentityPublicKeys: string[] = [];
  
  /** The client-provided identity unlock public key, which the client can query to form an identoty change key. */
  public sqrlServerUnlockPublicKey?: string;

  /** A client-provided validation key for validating an identity unlock. */
  public sqrlServerVerifyUnlockPublicKey?: string;

  /** Client has requested that this site only use its SQRL identity and not any alternate credentials. */
  public sqrlUseSqrlIdentityOnly: boolean = false;

  /**
   * Client has requested that this site disable identity recovery methods like security questions,
   * in favor solely of SQRL related identity recovery.
   */
  public sqrlHardLockSqrlUse: boolean = false;
}

class NutDBRecord extends NutInfo {
  // _id is implicit from NeDB.
  // tslint:disable-next-line
  public _id?: string;

  /** The URL containing the nut. */
  public url?: string;

  /** When the nut was created, for sweeping old entries. */
  public createdAt: Date;

  /** Whether the nut was successfully logged in. Updated on login. */
  public loggedIn: boolean = false;

  /** The primary public key of a user if a successful login was recorded for this nut. */
  public clientPrimaryIdentityPublicKey?: string;

  constructor(nut: string, url?: string, originalLoginNut?: string) {
    super();
    this.nut = nut;
    this.url = url;
    this.originalLoginNut = originalLoginNut;
    this.createdAt = new Date();
  }
}

/** Returned from /pollNut call. login.ejs makes use of this along with the cookie header. */
class NutPollResult {
  public loggedIn: boolean = false;
  public redirectTo?: string;
}
