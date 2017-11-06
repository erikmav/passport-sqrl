// Integration tests for an emulated SQRL and browser client
// calling a locally instantiated version of the test site.

import * as bodyParser from 'body-parser';
import { assert } from "chai";
import * as fs from 'fs';
import * as http from "http";
import * as request from 'request';
import * as requestPromise from 'request-promise-native';
import * as rimraf from 'rimraf';
import { TIFFlags } from '../passport-sqrl';
import { MockSQRLClient, ServerResponseInfo } from '../SqrlTests/MockSQRLClient';
import { ILogger, LogLevel } from '../testSite/Logging';
import * as testSite from '../testSite/TestSiteHandler';

const testSitePort = 14001;

class MockLogger implements ILogger {
  public logLevel: LogLevel;

  public error(message: string): void {
    console.log(`ERROR: ${message}`);
  }
  public warning(message: string): void {
    console.log(`Warn: ${message}`);
  }
  public info(message: string): void {
    console.log(message);
  }
  public debug(message: string): void {
    console.log(message);
  }
  public finest(message: string): void {
    console.log(message);
  }
}

describe('SqrlTestSite_Integration', () => {
  describe('InitialBrowserRequestNoCookieRedirectedToLogin', () => {
    it('should redirect a fresh, cookieless connection to the /login route', async () => {
      let mockLogger = new MockLogger();
      let site = new testSite.TestSiteHandler(mockLogger, testSitePort);

      let baseUrl = getWebBaseUrl();
      console.log(`Calling ${baseUrl}`);
      let htmlString: string = await requestPromise(baseUrl);
      assert(htmlString.indexOf("Welcome! Please log in with SQRL") > 0, htmlString);

      site.close();
    });
  });

  describe('GetLoginPageCallSqrlUrlFromExternalClient', () => {
    it('should allow an external client, simulating a browser plugin or phone app, to log the user in using the SQRL URL generated on a page', async () => {
      let mockLogger = new MockLogger();
      let site = new testSite.TestSiteHandler(mockLogger, testSitePort);

      let loginUrl = getWebBaseUrl() + '/login';
      console.log(`Calling ${loginUrl}`);
      let htmlString: string = await requestPromise(loginUrl);
      
      let startSqrlUrl = htmlString.indexOf('<a class="qr-code" href="');
      assert(startSqrlUrl > 0, 'SQRL URL link not found');
      startSqrlUrl += 25;

      let endSqrlUrl = htmlString.indexOf('">', startSqrlUrl);
      assert(endSqrlUrl > startSqrlUrl, 'SQRL URL end not found');

      let sqrlUrl = htmlString.substring(startSqrlUrl, endSqrlUrl);
      console.log(`Found SQRL URL ${sqrlUrl}`);
      
      // Generates a new unique identity at construction time.
      let sqrlClient = new MockSQRLClient(sqrlUrl);
      let queryResponse: ServerResponseInfo = await sqrlClient.performInitialQuery();
      assert.equal(1, queryResponse.supportedProtocolVersions.length);
      assert.equal(0, queryResponse.tifValues, "Expected no ID match to current server");
      console.log(`Next nut=${queryResponse.nextNut}`);
      console.log(`Next url=${queryResponse.nextRequestPathAndQuery}`);
      assert(queryResponse.nextRequestPathAndQuery.startsWith('/sqrlLogin?nut='));

      site.close();
    });
  });
});

function getWebBaseUrl(): string {
  return "http://localhost:" + testSitePort;
}

function pollForCondition(cond: () => boolean, done: (err?: Error) => void, start: number, timeoutMs: number) {
  setTimeout(() => {
    if (cond()) {
      done();
    } else {
      let elapsedMsec = new Date().getTime() - start;
      if (elapsedMsec >= timeoutMs) {
        done(new Error("Timeout"));
      } else {
        pollForCondition(cond, done, start, timeoutMs);
      }
    }
  }, 10);
}
