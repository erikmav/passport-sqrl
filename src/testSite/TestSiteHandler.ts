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
import * as path from 'path';
// import * as favicon from 'serve-favicon';
import { ILogger } from './Logging';

export class TestSiteHandler {
  private testSiteServer: http.Server;

  constructor(log: ILogger, port: number = 5858) {
    let webSiteDir = path.join(__dirname, 'WebSite');

    // From examples at https://github.com/feathersjs/feathers-typescript and
    // https://docs.feathersjs.com/api/express.html
    const app = express()
      // .use(favicon(__dirname + '/WebSite/favicon.ico'))  // First to handle quickly without passing through other middleware layers
      .use(bodyParser.json())  // Needed for parsing bodies (login)
      .use(bodyParser.urlencoded({extended: true}))  // Needed for parsing bodies (login)
      .use(express.static(webSiteDir));  // Serve static scripts and assets. Must come after non-file (e.g. REST) middleware

    this.testSiteServer = http.createServer(app);
    this.testSiteServer.listen(port);
  }

  public close(): void {
    this.testSiteServer.close();
  }
}
