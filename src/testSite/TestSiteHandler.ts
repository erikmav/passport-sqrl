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
import * as passport from 'passport';
import * as path from 'path';
import * as qr from 'qr-image';
import * as favicon from 'serve-favicon';
import { promisify } from 'util';
import { AuthCompletionInfo, ClientRequestInfo, SQRLStrategy, SQRLStrategyConfig } from '../passport-sqrl';
import { ILogger } from './Logging';

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

export class TestSiteHandler {
  private testSiteServer: http.Server;
  private sqrlPassportStrategy: SQRLStrategy;
  private nedb: neDB;
  private log: ILogger;

  constructor(log: ILogger, port: number = 5858) {
    this.log = log;
    let webSiteDir = path.join(__dirname, 'WebSite');
    const sqrlLoginRoute = '/sqrlLogin';
    const loginPageRoute = '/login';

    this.nedb = new neDB(<neDB.DataStoreOptions> { inMemoryOnly: true });

    this.sqrlPassportStrategy = new SQRLStrategy(<SQRLStrategyConfig> {
        secure: false,
        localDomainName: 'localhost',
        port: port,
        urlPath: sqrlLoginRoute,
      },
      (clientRequestInfo: ClientRequestInfo) => this.findAndUpdateOrCreateUser(clientRequestInfo));
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
        secret: 'SQRL-Test',
        resave: true,
        saveUninitialized: true
      }))
      .use(passport.initialize())
      .use(passport.session())
      .get(loginPageRoute, (req, res) => {
        this.log.debug('/login requested');
        let sqrlUrl = this.sqrlPassportStrategy.getSqrlUrl(req);
        let qrSvg = qr.imageSync(sqrlUrl, { type: 'svg', parse_url: true });
        res.render('login', {
          subpageName: 'Log In',
          sqrlUrl: sqrlUrl,
          sqrlQR: qrSvg
        });
      })
      .post(sqrlLoginRoute, passport.authenticate('sqrl', <passport.AuthenticateOptions> {
        successRedirect: '/',
        failureRedirect: loginPageRoute
      }))
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

    this.testSiteServer = http.createServer(app);
    log.info(`Test server listening on port ${port}`);
    this.testSiteServer.listen(port);
  }

  public close(): void {
    this.testSiteServer.close();
  }

  private findUser(sqrlPublicKey: string, done: (err: Error, doc: any) => void): void {
    // Treat the SQRL client's public key as a primary search key in the database.
    let userDBRecord = <UserDBRecord> {
      sqrlPrimaryIdentityPublicKey: sqrlPublicKey,
    };
    this.nedb.findOne(userDBRecord, done);
  }

  private async findAndUpdateOrCreateUser(clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> {
    try {
      // Treat the SQRL client's public key as a primary search key in the database.
      let searchRecord = <UserDBRecord> {
        sqrlPrimaryIdentityPublicKey: clientRequestInfo.primaryIdentityPublicKey,
      };
      let result = await this.nedb.findOneAsync(searchRecord);
      if (result == null) {
        // Not found by primary key. Maybe this is an identity change situation.
        // If a previous key was provided, search again.
        if (clientRequestInfo.previousIdentityPublicKey) {
          searchRecord.sqrlPrimaryIdentityPublicKey = clientRequestInfo.previousIdentityPublicKey;
          let prevKeyDoc: UserDBRecord = await this.nedb.findOneAsync(searchRecord);
          if (prevKeyDoc == null) {
            // Didn't already exist, create an initial version.
            let newRecord = UserDBRecord.newFromClientRequestInfo(clientRequestInfo);
            result = await this.nedb.insertAsync(newRecord);
          } else {
            // The user has specified a new primary key, rearrange the record and update.
            if (!prevKeyDoc.sqrlPreviousIdentityPublicKeys) {
              prevKeyDoc.sqrlPreviousIdentityPublicKeys = [];
            }
            prevKeyDoc.sqrlPreviousIdentityPublicKeys.push(clientRequestInfo.previousIdentityPublicKey);
            prevKeyDoc.sqrlPrimaryIdentityPublicKey = clientRequestInfo.primaryIdentityPublicKey;
            await this.nedb.updateAsync(searchRecord, prevKeyDoc);
            result = prevKeyDoc;
          }
        }
      }
      return <AuthCompletionInfo> { user: result };
    } catch (err) {
      return <AuthCompletionInfo> { err: err };
    }
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
  /* tslint:disable */ public _id?: string; /* tslint:enable */
  
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
