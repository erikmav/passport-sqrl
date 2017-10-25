// Integration tests for an emulated SQRL and browser client
// calling a locally instantiated version of the test site.

import * as bodyParser from 'body-parser';
import { assert } from "chai";
import * as fs from 'fs';
import * as http from "http";
import * as request from 'request';
import * as requestPromise from 'request-promise-native';
import * as rimraf from 'rimraf';
import { MockSQRLClient } from '../SqrlTests/MockSQRLClient';
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
