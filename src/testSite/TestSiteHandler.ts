// Module containing web site logic for the test site.
//
// URI space and site design notes
//
// Browser session cookies have been enabled for tracking the user
// session once logged in. The back-end database is an in-memory NeDB
// (https://github.com/louischatriot/nedb/) instance. The user
// profile schema information is in UserDBRecord.
//
// Browser page URI space:
//   / : Home page, hosted from index.ejs (template)
//   /login : GET for login page (login.ejs)
//   /sqrlLogin : GET/POST API endpoint for SQRL login

import * as bodyParser from 'body-parser';
import * as cookieParser from 'cookie-parser';
import * as ejs from 'ejs';
import * as express from 'express';
import * as expressLayouts from 'express-ejs-layouts';
import * as expressSession from 'express-session';
import * as fs from 'fs';
import * as http from 'http';
import * as neDB from 'nedb';
import * as os from 'os';
import * as passport from 'passport';
import * as path from 'path';
import * as qr from 'qr-image';
import * as favicon from 'serve-favicon';
import * as spdy from 'spdy';
import { promisify } from 'util';
import { AuthCompletionInfo, ClientRequestInfo, ILogger, ISQRLIdentityStorage, SQRLExpress, SQRLNutInfo, SQRLStrategy, SQRLStrategyConfig, SQRLUrlAndNut, TIFFlags } from '../passport-sqrl';

// TypeScript definitions for SPDY do not include an overload that allows the common
// Express app pattern as a param. Inject an overload to avoid compilation errors.
declare module 'spdy' {
  namespace server {
    export function create(options: ServerOptions, handler: express.Application): Server;
  }
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
const serverTlsCert = serverTlsCertDir + "/TestSite.Cert.pem";

export class TestSiteHandler implements ISQRLIdentityStorage {
  private testSiteServer: spdy.Server;
  private sqrlPassportStrategy: SQRLStrategy;
  private sqrlApiHandler: SQRLExpress;
  private userTable: neDB;
  private nutTable: neDB;
  private log: ILogger;

  constructor(log: ILogger, port: number = 5858, domainName: string | null = null) {
    this.log = log;
    let webSiteDir = path.join(__dirname, 'WebSite');
    const sqrlApiRoute = '/sqrl';
    const sqrlLoginRoute = '/sqrlLogin';
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

    this.sqrlApiHandler = new SQRLExpress(this, this.log, sqrlConfig);

    this.sqrlPassportStrategy = new SQRLStrategy(sqrlConfig,
      (clientRequestInfo: ClientRequestInfo) => this.query(clientRequestInfo),
      (clientRequestInfo: ClientRequestInfo) => this.ident(clientRequestInfo),
      (clientRequestInfo: ClientRequestInfo) => this.disable(clientRequestInfo),
      (clientRequestInfo: ClientRequestInfo) => this.enable(clientRequestInfo),
      (clientRequestInfo: ClientRequestInfo) => this.remove(clientRequestInfo));
    passport.use(this.sqrlPassportStrategy);
    passport.serializeUser((user: UserDBRecord, done) => done(null, user.sqrlPrimaryIdentityPublicKey));
    passport.deserializeUser((id: any, done: (err: Error, doc: any) => void) => this.findUser(id, done));

    // Useful: http://toon.io/understanding-passportjs-authentication-flow/
    const app = express()
      .set('view engine', 'ejs')
      .set('views', path.join(__dirname, 'views'))
      .use(expressLayouts)
      .use(favicon(webSiteDir + '/favicon.ico'))  // First to handle quickly without passing through other middleware layers
      .use(cookieParser())
      .use(bodyParser.json())  // Needed for parsing bodies (login)
      .use(bodyParser.urlencoded({extended: true}))  // Needed for parsing bodies (login)
      .use(expressSession({  // Session load+decrypt support, must come before passport.session
        secret: 'SQRL-Test',  // SECURITY: If reusing site code, you need to supply this secret from a real secret store.
        resave: true,
        saveUninitialized: true
      }))
      .use(passport.initialize())
      .use(passport.session())
      .get(loginPageRoute, (req, res) => {
        this.log.debug('/login requested');
        let urlAndNut: SQRLUrlAndNut = this.sqrlPassportStrategy.getSqrlUrl(req);
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

      // NOTE: No SuccessRedirect, FailureRedirect - this is a web API more than a normal login endpoint.
      // There can be multiple round-trips to this endpoint, typically for a query followed
      // by a login request.
      .post(sqrlLoginRoute, passport.authenticate('sqrl'))

      // TODO: Keep? Refactor?
      .post(sqrlApiRoute, this.sqrlApiHandler.handleSqrlApi)
      
      // Used by login.ejs
      .get(pollNutRoute, (req, res) => {
        if (req.params.nut) {
          this.getNutInfoAsync(req.params.nut)
            .then(nutInfo => {
              let nutRecord = <NutDBRecord> nutInfo;  // Full record is returned below.
              if (!nutRecord) {
                this.log.debug(`pollNut: ${req.params.nut}: No nut record, returning 404`);
                res.statusCode = 404;
                res.end();
              } else if (!nutRecord.loggedIn || !nutRecord.clientPrimaryIdentityPublicKey) {
                this.log.finest(() => `pollNut: ${req.params.nut}: Nut not logged in`);
                res.send(<NutPollResult> { loggedIn: false });
              } else {
                this.findUser(nutRecord.clientPrimaryIdentityPublicKey, (err: Error, userDBRecord: UserDBRecord | null) => {
                  if (err) {
                    this.log.debug(`pollNut: ${req.params.nut}: Error finding user: ${err}`);
                    res.statusCode = 500;
                    res.send(err.toString());
                  } else {
                    this.log.debug(`pollNut: ${req.params.nut}: Nut logged in, logging user in via PassportJS`);
                    // Ensure the cookie header for the response is set the way Passport normally does it.
                    req.login(userDBRecord, loginErr => {
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
      .get('/', (req, res) => {
        this.log.debug('/ requested');
        if (!req.user) {
          res.redirect(loginPageRoute);
        } else {
          res.render('index', {
            subpageName: 'Main',
            username: req.user.name,  // TODO get user, other info from client session cookie ref to back-end session store
            sqrlPublicKey: req.user.sqrlPrimaryIdentityPublicKey
          });
        }
      })
      .use(express.static(webSiteDir));  // Serve static scripts and assets. Must come after non-file (e.g. templates, REST) middleware

    this.testSiteServer = spdy.server.create(<spdy.server.ServerOptions> {
      // Leaf cert PEM files for server certificate. See CreateLeaf.cmd and related scripts.
      cert: fs.readFileSync(serverTlsCert),
      key: fs.readFileSync(serverTlsKey),

      // SPDY module supports Bunyan.
      // TODO: Seems like we need a way to bypass TS strong typing:  log: log,

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
  }

  public close(): void {
    this.testSiteServer.close();
  }

  /**
   * When we issue a SQRL URL, the nut (and the URL itself) act as a one-time nonce
   * for that specific client. (Use of HTTPS for the site prevents disclosure to
   * a man-in-the-middle.) We need to track the nut values for phone login.
   * There are two important cases:
   * 
   * 1. Login is performed in a browser with a browser plugin. The plugin will
   *    specify the cps option to the SQRL API, which means the plugin acts as
   *    a go-between, sending the client's public key and signed SQRL URL, and
   *    on 200 Success it uses the cps response as a success redirect. In this
   *    case, the full query is handled by the plugin.
   * 
   * 2. Login is performed by a phone against the QR-Code of the URL. The phone
   *    SQRL app contacts the SQRL API and presents the client's public key and
   *    signed SQRL URL, but (usually) without the cps option, as the phone app
   *    cannot redirect the browser. For this case, we need to track recent
   *    nut values and have the page poll an ajax REST endpoint seeing if the nut
   *    was logged in. In that case we log the browser on and return the usual
   *    ambient user profile reference in the cookie.
   */
  public async nutIssuedToClientAsync(sqrlUrlAndNut: SQRLUrlAndNut, originalLoginNut?: string): Promise<void> {
    return (<any> this.nutTable).insertAsync(new NutDBRecord(sqrlUrlAndNut.nutString, sqrlUrlAndNut.url, originalLoginNut));
  }

  public async getNutInfoAsync(nut: string): Promise<SQRLNutInfo | null> {
    return this.getNutRecordAsync(nut);  // NutDBRecord derives from SQRLNutInfo.
  }

  public async query(clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> {
    // SQRL query. We don't create any new user records, just return whether we know about the user.
    let authInfo: AuthCompletionInfo = await this.findUserByEitherKey(clientRequestInfo);
    if (authInfo.user && clientRequestInfo.returnSessionUnlockKey) {
      let user = <UserDBRecord> authInfo.user;
      authInfo.sessionUnlockKey = user.sqrlServerUnlockPublicKey;
    }
    return authInfo;
  }

  public async ident(clientRequestInfo: ClientRequestInfo, nutInfo: SQRLNutInfo): Promise<AuthCompletionInfo> {
    // SQRL login request.
    let authInfo: AuthCompletionInfo = await this.findUserByEitherKey(clientRequestInfo);
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

  public disable(clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> {
    // SQRL identity disable request.
    return Promise.resolve(new AuthCompletionInfo());  // TODO
  }

  public enable(clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> {
    // SQRL identity enable request.
    return Promise.resolve(new AuthCompletionInfo());  // TODO
  }

  public remove(clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> {
    // SQRL identity remove request.
    return Promise.resolve(new AuthCompletionInfo());  // TODO
  }

  private async getNutRecordAsync(nut: string): Promise<NutDBRecord | null> {
    let searchRecord = { nut: nut };
    return (<any> this.nutTable).findOneAsync(searchRecord);
  }

  private findUser(sqrlPublicKey: string, done: (err: Error, doc: any) => void): void {
    // Treat the SQRL client's public key as a primary search key in the database.
    let userDBRecord = <UserDBRecord> {
      sqrlPrimaryIdentityPublicKey: sqrlPublicKey,
    };
    this.userTable.findOne(userDBRecord, done);
  }

  private async findUserByEitherKey(clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> {
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

  private async findAndUpdateOrCreateUser(clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> {
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
class UserDBRecord {
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
  public sqrlPrimaryIdentityPublicKey: string;

  /** Up to four previously seen previous identity keys, for reference. */
  public sqrlPreviousIdentityPublicKeys: string[] = [];
  
  /** The client-provided identity unlock public key, which the client can query to form an identoty change key. */
  public sqrlServerUnlockPublicKey: string;

  /** A client-provided validation key for validating an identity unlock. */
  public sqrlServerVerifyUnlockPublicKey: string;

  /** Client has requested that this site only use its SQRL identity and not any alternate credentials. */
  public sqrlUseSqrlIdentityOnly: boolean = false;

  /**
   * Client has requested that this site disable identity recovery methods like security questions,
   * in favor solely of SQRL related identity recovery.
   */
  public sqrlHardLockSqrlUse: boolean = false;
}

class NutDBRecord extends SQRLNutInfo {
  // _id is implicit from NeDB.
  // tslint:disable-next-line
  public _id?: string;

  /** The URL containing the nut. */
  public url?: string;

  /** When the nut was created, for sweeping old entries. */
  public createdAt: Date;

  /** Whether the nut was successfully logged in. Updated on login. */
  public loggedIn: boolean;

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
  public loggedIn: boolean;
  public redirectTo?: string;
}
