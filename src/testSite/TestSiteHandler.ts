// Module containing web site logic for the test site.
//
// URI space and site design notes
//
// Browser page URI space:
//   / : Home page, hosted from index.html
//   /sqrl : POST endpoint for SQRL login
//
// Logging: Bunyan logs in use for general logging to the console.

import * as bodyParser from 'body-parser';
import * as express from 'express';
import * as fs from 'fs';
import * as http from 'http';
import * as passport from 'passport';
import * as path from 'path';
import * as favicon from 'serve-favicon';
import { SQRLStrategy, SQRLStrategyConfig } from '../passport-sqrl';
import { ILogger } from './Logging';

export class TestSiteHandler {
  private testSiteServer: http.Server;
  private sqrlPassportStrategy: SQRLStrategy;

  constructor(log: ILogger, port: number = 5858) {
    let webSiteDir = path.join(__dirname, 'WebSite');
    const loginRoute = '/sqrlLogin';

    this.sqrlPassportStrategy = new SQRLStrategy(<SQRLStrategyConfig> {
        secure: false,
        localDomainName: 'localhost',
        urlPath: loginRoute,
        serverFriendlyName: 'SQRL Test!'
      },
      (clientPublicKey, done) => {
        done();
      });
    passport.use(this.sqrlPassportStrategy);

    const app = express()
      .use(favicon(webSiteDir + '/favicon.ico'))  // First to handle quickly without passing through other middleware layers
      .use(bodyParser.json())  // Needed for parsing bodies (login)
      .use(bodyParser.urlencoded({extended: true}))  // Needed for parsing bodies (login)
      .post(loginRoute, passport.authenticate('sqrl', {
        successRedirect: '/',
        failureRedirect: loginRoute
      }))
      .use(express.static(webSiteDir));  // Serve static scripts and assets. Must come after non-file (e.g. REST) middleware

    this.testSiteServer = http.createServer(app);
    this.testSiteServer.listen(port);
  }

  public close(): void {
    this.testSiteServer.close();
  }
}
