// Integration tests for an emulated SQRL and browser client
// calling a locally instantiated version of the test site.

import * as bodyParser from 'body-parser';
import { assert } from "chai";
import * as fs from 'fs';
import * as request from 'request';
import * as requestPromise from 'request-promise-native';
import * as rimraf from 'rimraf';
import { ILogger, LogLevel, TIFFlags } from '../passport-sqrl';
import { MockLogger } from '../SqrlTests/MockLogger';
import { MockSQRLClient, ServerResponseInfo } from '../SqrlTests/MockSQRLClient';
import * as testSite from '../testSite/TestSiteHandler';

const testSitePort = 14001;
const serverTlsCertDir = __dirname;
const serverTlsCert = serverTlsCertDir + "/TestSite.FullChain.Cert.pem";

describe('SqrlTestSite_Integration', () => {
  describe('InitialBrowserRequestNoCookieRedirectedToLogin', () => {
    it('should redirect a fresh, cookieless connection to the /login route', async () => {
      let mockLogger = new MockLogger();
      let site = new testSite.TestSiteHandler(mockLogger, testSitePort, 'localhost');

      let baseUrl = getWebBaseUrl();
      let requestOpt = createRequestJsOptions();
      console.log(`Calling ${baseUrl}`);
      let htmlString: string = await requestPromise(baseUrl, requestOpt);
      assert(htmlString.indexOf("Welcome! Please log in with SQRL") > 0, htmlString);

      site.close();
    });
  });

  describe('GetLoginPageCallSqrlUrlFromExternalClient', () => {
    it('should allow an external client, simulating a browser plugin or phone app, to log the user in using the SQRL URL generated on a page', async () => {
      let mockLogger = new MockLogger();
      let site = new testSite.TestSiteHandler(mockLogger, testSitePort, 'localhost');

      let loginUrl = getWebBaseUrl() + '/login';
      let requestOpt = createRequestJsOptions();
      console.log(`Calling ${loginUrl}`);
      let htmlString: string = await requestPromise(loginUrl, requestOpt);
      
      let startSqrlUrl = htmlString.indexOf('<a class="qr-code" href="');
      assert(startSqrlUrl > 0, 'SQRL URL link not found');
      startSqrlUrl += 25;

      let endSqrlUrl = htmlString.indexOf(' ', startSqrlUrl) - 1/*end quote*/;
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
      assert.isTrue((queryResponse.nextRequestPathAndQuery || '').startsWith('/sqrl?nut='));

      site.close();
    });
  });
});

function getWebBaseUrl(): string {
  return "https://localhost:" + testSitePort;
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

function createRequestJsOptions(): request.CoreOptions {
  // http://www.benjiegillam.com/2012/06/node-dot-js-ssl-certificate-chain/
  let testSiteCert = fs.readFileSync(serverTlsCert);
  let certValidationList = [ testSiteCert ];

  return <request.CoreOptions> {
    ca: certValidationList,
    agentOptions: {
      ca: certValidationList
    },
    rejectUnauthorized: false
  };
}
