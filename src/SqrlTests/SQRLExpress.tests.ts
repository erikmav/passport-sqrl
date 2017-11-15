// Unit test suite for SQRLExpress code.

import { assert } from "chai";
import * as express from 'express';
import { AuthCallback, AuthCompletionInfo, AuthenticateAsyncResult, ClientRequestInfo, ILogger, ISQRLIdentityStorage, NutInfo, SQRLExpress, SQRLStrategyConfig, TIFFlags, UrlAndNut } from '../passport-sqrl';
import { MockLogger } from '../SqrlTests/MockLogger';
import { MockSQRLClient, ServerResponseInfo } from './MockSqrlClient';

describe('SQRLExpress', () => {
  describe('getSqrlUrlNoNutGenerator', () => {
    it('should generate a 128-bit random value as the nut if no nut generator override is provided', () => {
      let storage = new MockSQRLIdentityStorage();
      let sqrl = new MockSQRLExpress(storage, new MockLogger(), <SQRLStrategyConfig> {
          localDomainName: 'domain.com',
          urlPath: '/login',
          domainExtension: 6,
        });

      let urlAndNut: UrlAndNut = sqrl.getSqrlUrl(<express.Request> { });
      assert.equal(urlAndNut.url.substring(0, 28), 'sqrl://domain.com/login?nut=');
      // 22 characters of base64 for 128 bits - should be random
      assert.equal(urlAndNut.url.substring(28 + 22), "&x=6");
      assert.isNotNull(urlAndNut.nut);

      assert.equal(storage.queryCalls, 0);
      assert.equal(storage.identCalls, 0);
      assert.equal(storage.disableCalls, 0);
      assert.equal(storage.enableCalls, 0);
      assert.equal(storage.removeCalls, 0);
    });
  });

  describe('getSqrlUrlCustomNutGenerator', () => {
    it('should accept a custom nut value from a nut generator specified by caller', () => {
      let storage = new MockSQRLIdentityStorage();
      let sqrl = new MockSQRLExpress(storage, new MockLogger(), <SQRLStrategyConfig> {
        localDomainName: 'domain.com',
        urlPath: '/login',
        nutGenerator: (req: express.Request): string | Buffer => {
          return "nuts!";
        }
      });

      let urlAndNut: UrlAndNut = sqrl.getSqrlUrl(<express.Request> { });
      assert.equal(urlAndNut.url, 'sqrl://domain.com/login?nut=nuts!');
      assert.equal(urlAndNut.nut, 'nuts!');

      assert.equal(storage.queryCalls, 0);
      assert.equal(storage.identCalls, 0);
      assert.equal(storage.disableCalls, 0);
      assert.equal(storage.enableCalls, 0);
      assert.equal(storage.removeCalls, 0);
    });
  });

  describe('queryIdentSingleIdentitySucceeds', () => {
    it('should call the user auth callback with expected values', async () => {
      let queryRequestInfo: ClientRequestInfo | null;
      let storage = new MockSQRLIdentityStorage();
      let sqrl = new MockSQRLExpress(storage, new MockLogger(), <SQRLStrategyConfig> {
          localDomainName: 'domain.com',
          clientLoginSuccessUrl: '/',
          clientCancelAuthUrl: '/login'
        });
      storage.onQuery = (clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> => {
        queryRequestInfo = clientRequestInfo;
        return Promise.resolve(<AuthCompletionInfo> {
          tifValues: 0
        });
      };
      storage.onIdent = (clientRequestInfo: ClientRequestInfo): Promise<AuthCompletionInfo> => {
        queryRequestInfo = clientRequestInfo;
        return Promise.resolve(<AuthCompletionInfo> {
          tifValues: TIFFlags.CurrentIDMatch,
          user: { name: "bob" }
        });
      };
      storage.onGetNutInfo = (nut: string): NutInfo | null => {
        if (nut === '1234') {
          return <NutInfo> { nut: '1234' };
        }
        return null;
      };

      // Initial query call.
      let client = new MockSQRLClient('sqrl://foo.com/login?nut=1234');
      let authResult: AuthenticateAsyncResult = await sqrl.authenticateAsync(<express.Request> {
        method: "POST",
        body: client.generatePostBody('query')
      });
      assert.equal(authResult.httpResponseCode, 200);
      assert.isUndefined(authResult.user, 'A query should not actually return the user');
      assert.equal(storage.nutIssuedToClientCalls, 1);
      assert.equal(storage.getNutInfoCalls, 1);
      assert.equal(storage.queryCalls, 1);
      assert.equal(storage.identCalls, 0);
      assert.equal(storage.disableCalls, 0);
      assert.equal(storage.enableCalls, 0);
      assert.equal(storage.removeCalls, 0);
      assert.isDefined(authResult.body);
      let res: ServerResponseInfo = client.parseServerBody(authResult.body || '');
      assert.equal(res.tifValues, 0, 'Expected no match returned in mock');

      // Follow-up ident call.
      authResult = await sqrl.authenticateAsync(<express.Request> {
        method: "POST",
        body: client.generatePostBody('ident')
      });
      assert.equal(authResult.httpResponseCode, 200, 'Success expected');
      assert(authResult.user, 'User record should be present');
      assert.equal('bob', authResult.user.name);
      assert.equal(storage.nutIssuedToClientCalls, 2);
      assert.equal(storage.getNutInfoCalls, 2);
      assert.equal(storage.queryCalls, 1);
      assert.equal(storage.identCalls, 1);
      assert.equal(storage.disableCalls, 0);
      assert.equal(storage.enableCalls, 0);
      assert.equal(storage.removeCalls, 0);
      assert.isDefined(authResult.body);
      res = client.parseServerBody(authResult.body || '');
      assert.equal(res.tifValues, TIFFlags.CurrentIDMatch);
    });
  });

  describe('queryUnknownSqrlVersionFails', () => {
    it('should throw if the SQRL version is not supported', async () => {
      let storage = new MockSQRLIdentityStorage();
      let sqrl = new MockSQRLExpress(storage, new MockLogger(), <SQRLStrategyConfig> {
          localDomainName: 'domain.com',
          clientLoginSuccessUrl: '/',
          clientCancelAuthUrl: '/login'
        });

      let client = new MockSQRLClient('sqrl://foo.com/login?nut=1234', 0, /*sqrlVersion:*/1000);
      try {
        let authResult: AuthenticateAsyncResult = await sqrl.authenticateAsync(<express.Request> {
          method: "POST",
          body: client.generatePostBody('query')
        });
        assert.fail('Expected exception not thrown');
      } catch (e) {
        let err = <Error> e;
        assert.isTrue(err.message.indexOf('This server only handles SQRL protocol revision 1') >= 0);
      }
    });
  });
});

class MockSQRLIdentityStorage implements ISQRLIdentityStorage {
  public queryCalls = 0;
  public identCalls = 0;
  public disableCalls = 0;
  public enableCalls = 0;
  public removeCalls = 0;
  public nutIssuedToClientCalls = 0;
  public getNutInfoCalls = 0;
  
  public onQuery: AuthCallback;
  public onIdent: AuthCallback;
  public onDisable: AuthCallback;
  public onEnable: AuthCallback;
  public onRemove: AuthCallback;
  public onNutIssuedToClient: (urlAndNut: UrlAndNut, originalLoginNut?: string) => void;
  public onGetNutInfo: (nut: string) => NutInfo | null;

  private issuedNuts: any = {};

  public nutIssuedToClientAsync(urlAndNut: UrlAndNut, originalLoginNut?: string): Promise<void> {
    this.nutIssuedToClientCalls++;
    if (this.onNutIssuedToClient) {
      this.onNutIssuedToClient(urlAndNut, originalLoginNut);
      return Promise.resolve();
    }
    this.issuedNuts[urlAndNut.nutString] = <NutInfo> {
      nut: urlAndNut.nutString,
      originalLoginNut: originalLoginNut
    };
    return Promise.resolve();
  }

  public getNutInfoAsync(nut: string): Promise<NutInfo | null> {
    this.getNutInfoCalls++;
    if (this.onGetNutInfo) {
      return Promise.resolve(this.onGetNutInfo(nut));
    }
    return Promise.resolve(this.issuedNuts[nut]);
  }
  
  public query(clientRequestInfo: ClientRequestInfo, nutInfo: NutInfo): Promise<AuthCompletionInfo> {
    this.queryCalls++;
    if (this.onQuery) {
      return this.onQuery(clientRequestInfo);
    }
    return Promise.resolve(<AuthCompletionInfo> {});
  }

  public ident(clientRequestInfo: ClientRequestInfo, nutInfo: NutInfo): Promise<AuthCompletionInfo> {
    this.identCalls++;
    if (this.onIdent) {
      return this.onIdent(clientRequestInfo);
    }
    return Promise.resolve(<AuthCompletionInfo> {});
  }

  public disable(clientRequestInfo: ClientRequestInfo, nutInfo: NutInfo): Promise<AuthCompletionInfo> {
    this.disableCalls++;
    if (this.onDisable) {
      return this.onDisable(clientRequestInfo);
    }
    return Promise.resolve(<AuthCompletionInfo> {});
  }

  public enable(clientRequestInfo: ClientRequestInfo, nutInfo: NutInfo): Promise<AuthCompletionInfo> {
    this.enableCalls++;
    if (this.onEnable) {
      return this.onEnable(clientRequestInfo);
    }
    return Promise.resolve(<AuthCompletionInfo> {});
  }

  public remove(clientRequestInfo: ClientRequestInfo, nutInfo: NutInfo): Promise<AuthCompletionInfo> {
    this.removeCalls++;
    if (this.onRemove) {
      return this.onRemove(clientRequestInfo);
    }
    return Promise.resolve(<AuthCompletionInfo> {});
  }
}

/** Exposes base class protected members as public for unit testing. */
class MockSQRLExpress extends SQRLExpress {
  public storage: MockSQRLIdentityStorage;

  constructor(mockStorage: MockSQRLIdentityStorage, log: ILogger, config: SQRLStrategyConfig) {
    super(mockStorage, log, config);
    this.storage = mockStorage;
  }

  public async authenticateAsync(req: express.Request): Promise<AuthenticateAsyncResult> {
    return super.authenticateAsync(req);
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
