// Unit test suite for SQRLFactory code.

import { assert } from "chai";
import * as express from 'express';
import { AuthCallback, AuthCompletionInfo, AuthenticateAsyncResult, ClientRequestInfo, SQRLStrategy, SQRLStrategyConfig, SQRLUrlAndNut, TIFFlags } from '../passport-sqrl';
import { MockSQRLClient, ServerResponseInfo } from './MockSqrlClient';

describe('SQRLStrategy', () => {
  describe('getSqrlUrlNoNutGenerator', () => {
    it('should generate a 128-bit random value as the nut if no nut generator override is provided', () => {
      let sqrl = new MockSQRLStrategy(<SQRLStrategyConfig> {
          secure: false,
          localDomainName: 'domain.com',
          urlPath: '/login',
          domainExtension: 6,
        });

      let urlAndNut: SQRLUrlAndNut = sqrl.getSqrlUrl(<express.Request> { });
      assert.equal(urlAndNut.url.substring(0, 27), 'qrl://domain.com/login?nut=');
      // 22 characters of base64 for 128 bits - should be random
      assert.equal(urlAndNut.url.substring(27 + 22), "&x=6");
      assert.isNotNull(urlAndNut.nut);

      assert.equal(sqrl.queryCalls, 0);
      assert.equal(sqrl.identCalls, 0);
      assert.equal(sqrl.disableCalls, 0);
      assert.equal(sqrl.enableCalls, 0);
      assert.equal(sqrl.removeCalls, 0);
    });
  });

  describe('getSqrlUrlCustomNutGenerator', () => {
    it('should accept a custom nut value from a nut generator specified by caller', () => {
      let sqrl = new MockSQRLStrategy(<SQRLStrategyConfig> {
        secure: true,
        localDomainName: 'domain.com',
        urlPath: '/login',
        nutGenerator: (req: express.Request): string | Buffer => {
          return "nuts!";
        }
      });

      let urlAndNut: SQRLUrlAndNut = sqrl.getSqrlUrl(<express.Request> { });
      assert.equal(urlAndNut.url, 'sqrl://domain.com/login?nut=nuts!');
      assert.equal(urlAndNut.nut, 'nuts!');

      assert.equal(sqrl.queryCalls, 0);
      assert.equal(sqrl.identCalls, 0);
      assert.equal(sqrl.disableCalls, 0);
      assert.equal(sqrl.enableCalls, 0);
      assert.equal(sqrl.removeCalls, 0);
    });
  });

  describe('strategyName', () => {
    it('should return the expected value for the name field', () => {
      let sqrl = new MockSQRLStrategy(<SQRLStrategyConfig> {
          localDomainName: 'domain.com'
        });

      assert.equal('sqrl', sqrl.name);
    });
  });

  describe('queryIdentSingleIdentitySucceeds', () => {
    it('should call the user auth callback with expected values', async () => {
      let queryRequestInfo: ClientRequestInfo | null;

      let sqrl = new MockSQRLStrategy(<SQRLStrategyConfig> {
          localDomainName: 'domain.com',
          clientLoginSuccessUrl: '/',
          clientCancelAuthUrl: '/login'
        },
        /*query:*/(clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> => {
          queryRequestInfo = clientRequestInfo;
          return Promise.resolve(<AuthCompletionInfo> {
            tifValues: TIFFlags.CurrentIDMatch
          });
        });

      // Initial query call.
      let client = new MockSQRLClient('sqrl://foo.com/login?nut=1234');
      let authResult: AuthenticateAsyncResult = await sqrl.authenticateAsync(<express.Request> {
        method: "POST",
        body: client.generatePostBody('query')
      });
      assert.isTrue(authResult.callFail, 'Result should want to call Passport fail() on a query since user is not known yet');
      assert.equal(authResult.httpResponseCode, 200, 'Fail tells Passport not to store a use in the ambient session, but we still return 200 to the SQRL client');
      assert.isUndefined(authResult.user, 'A query should not actually return the user');
      assert.equal(sqrl.queryCalls, 1);
      assert.equal(sqrl.identCalls, 0);
      assert.equal(sqrl.disableCalls, 0);
      assert.equal(sqrl.enableCalls, 0);
      assert.equal(sqrl.removeCalls, 0);
      let res: ServerResponseInfo = client.parseServerBody(authResult.body);
      assert.equal(res.tifValues, TIFFlags.CurrentIDMatch, 'Expected pass-through of identity match returned in mock');

      // Follow-up ident call.
      authResult = await sqrl.authenticateAsync(<express.Request> {
        method: "POST",
        body: client.generatePostBody('ident')
      });
      assert.equal(sqrl.errorCalls, 0, 'Base error() should not have been called');
      assert.equal(sqrl.failCalls, 1, 'Leftover query value');
      assert.equal(sqrl.successCalls, 1, 'Base success() should have been called ident success');
      assert.equal('bob', sqrl.successUser.name);
      assert.equal('info!', sqrl.successInfo);
      assert.equal(sqrl.queryCalls, 1);
      assert.equal(sqrl.identCalls, 1);
      assert.equal(sqrl.disableCalls, 0);
      assert.equal(sqrl.enableCalls, 0);
      assert.equal(sqrl.removeCalls, 0);
      res = client.parseServerBody(authResult.body);
      assert.equal(res.tifValues, TIFFlags.CurrentIDMatch);
    });
  });
});

/** Overrides Passport Strategy error(), success() calls from base PassportJS Strategy to hook for unit testing. */
class MockSQRLStrategy extends SQRLStrategy {
  public errorCalls: number = 0;
  public errorReturned: Error;
  public successCalls: number = 0;
  public successUser: any;
  public successInfo: any;
  public failCalls: number = 0;
  public failChallenge: any;
  public failStatus: number;

  public queryCalls = 0;
  public identCalls = 0;
  public disableCalls = 0;
  public enableCalls = 0;
  public removeCalls = 0;
  
  constructor(
      config: SQRLStrategyConfig,
      query?: AuthCallback,
      ident?: AuthCallback,
      disable?: AuthCallback,
      enable?: AuthCallback,
      remove?: AuthCallback) {
    super(config,
      (clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> => {
        this.queryCalls++;
        if (query) {
          return query(clientRequestInfo);
        }
        return Promise.resolve(<AuthCompletionInfo> {});
      },
      (clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> => {
        this.identCalls++;
        if (ident) {
          return ident(clientRequestInfo);
        }
        return Promise.resolve(<AuthCompletionInfo> {});
      },
      (clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> => {
        this.disableCalls++;
        if (disable) {
          return disable(clientRequestInfo);
        }
        return Promise.resolve(<AuthCompletionInfo> {});
      },
      (clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> => {
        this.enableCalls++;
        if (enable) {
          return enable(clientRequestInfo);
        }
        return Promise.resolve(<AuthCompletionInfo> {});
      },
      (clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> => {
        this.removeCalls++;
        if (remove) {
          return remove(clientRequestInfo);
        }
        return Promise.resolve(<AuthCompletionInfo> {});
      });
  }
    
  public error(err: Error) {
    this.errorCalls++;
    this.errorReturned = err;
  }

  public success(user: any, info: any) {
    this.successCalls++;
    this.successUser = user;
    this.successInfo = info;
  }

  public fail(challenge: any, status: number = NaN) {
    this.failCalls++;
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
