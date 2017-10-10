// Unit test suite for SQRLFactory code.

import { assert } from "chai";
import * as express from 'express';
import { AuthCallback, AuthCompletionInfo, ClientRequestInfo, SQRLStrategy, SQRLStrategyConfig } from '../passport-sqrl';

describe('SQRLStrategy', () => {
  describe('getSqrlUrlNoNutGenerator', () => {
    it('should generate a 128-bit random value as the nut if no nut generator override is provided', () => {
      let authCalled = false;
      
      let sqrl = new SQRLStrategy(<SQRLStrategyConfig> {
          secure: false,
          localDomainName: 'domain.com',
          urlPath: '/login',
          domainExtension: 6,
          serverFriendlyName: 'friends!',
        },
        (clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> => {
          authCalled = true;
          return Promise.resolve(<AuthCompletionInfo> {});
        });

      let url = sqrl.getSqrlUrl(<express.Request> { });
      assert.equal(url.substring(0, 27), 'qrl://domain.com/login?nut=');
      // 22 characters of base64 for 128 bits - should be random
      assert.equal(url.substring(27 + 22), "&x=6&sfn=ZnJpZW5kcyE");

      assert.isFalse(authCalled);
    });
  });

  describe('getSqrlUrlCustomNutGenerator', () => {
    it('should accept a custom nut value from a nut generator specified by caller', () => {
      let authCalled = false;
      
      let sqrl = new SQRLStrategy(<SQRLStrategyConfig> {
          secure: true,
          localDomainName: 'domain.com',
          urlPath: '/login',
          serverFriendlyName: 'enemy',
          nutGenerator: (req: express.Request): string | Buffer => {
            return "nuts!";
          }
        },
        (clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> => {
          authCalled = true;
          return Promise.resolve(<AuthCompletionInfo> {});
        });

      let url = sqrl.getSqrlUrl(<express.Request> { });
      assert.equal(url, 'sqrl://domain.com/login?nut=nuts!&sfn=ZW5lbXk');

      assert.isFalse(authCalled);
    });
  });

  describe('strategyName', () => {
    it('should return the expected value for the name field', () => {
      let sqrl = new SQRLStrategy(<SQRLStrategyConfig> {
          localDomainName: 'domain.com'
        },
        (clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> => {
          return Promise.resolve(<AuthCompletionInfo> {});
        });

      assert.equal('sqrl', sqrl.name);
    });
  });

  describe('mockPostCorrectSignaturesValidUserReturnsSuccess', () => {
    it('should call the user auth callback with expected values', done => {
      let requestInfo: ClientRequestInfo | null = null;

      let sqrl = new MockSQRLStrategy(<SQRLStrategyConfig> {
          localDomainName: 'domain.com'
        },
        (clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> => {
          requestInfo = clientRequestInfo;
          return Promise.resolve(<AuthCompletionInfo> {
            user: { name: 'bob' },
            info: 'info!'
          });
        });

      // TODO: Change request body to a POST set to the values a real client would send.
      sqrl.authenticate(<express.Request> {
        method: "POST",
        body: {
          client: "client1",
          server: "server1",
          ids: "ids1"
        }
      });

      // authenticate() logic is aync and may not be done by the time we get here.
      pollForCondition(() => sqrl.successCalled, done, new Date().getTime(), 1000, () => {
        assert.isNotNull(requestInfo, 'The callback should have been called');
        // assert.equal(requestInfo
        assert.isFalse(sqrl.errorCalled, 'Base error() should not have been called');
        assert.isFalse(sqrl.failCalled, 'Base fail() should not have been called');
        assert.isTrue(sqrl.successCalled, 'Base success() should have been called');
        assert.equal('bob', sqrl.successUser.name);
        assert.equal('info!', sqrl.successInfo);
      });
    });
  });
});

/** Overrides error(), success() calls from base PassportJS Streategy to hook for unit testing. */
class MockSQRLStrategy extends SQRLStrategy {
  public errorCalled: boolean = false;
  public errorReturned: Error;
  public successCalled: boolean = false;
  public successUser: any;
  public successInfo: any;
  public failCalled: boolean = false;
  public failChallenge: any;
  public failStatus: number;

  constructor(config: SQRLStrategyConfig, authCallback: AuthCallback) {
    super(config, authCallback);
  }
    
  public error(err: Error) {
    this.errorCalled = true;
    this.errorReturned = err;
  }

  public success(user: any, info: any) {
    this.successCalled = true;
    this.successUser = user;
    this.successInfo = info;
  }

  public fail(challenge: any, status: number = NaN) {
    this.failCalled = true;
    this.failChallenge = challenge;
    this.failStatus = status;
  }
}

function pollForCondition(cond: () => boolean, done: (err?: Error) => void, startTime: number, timeoutMs: number, onCond: () => void) {
  setTimeout(() => {
    if (cond()) {
      try {
        onCond();
        done();
      } catch (err) {
        done(err);
      }
    } else {
      let elapsedMsec = new Date().getTime() - startTime;
      if (elapsedMsec >= timeoutMs) {
        done(new Error("Timeout"));
      } else {
        pollForCondition(cond, done, startTime, timeoutMs, onCond);
      }
    }
  }, 10);
}
