// Unit test suite for SQRLFactory code.

import { assert } from "chai";
import * as express from 'express';
import { SQRLClientRequestInfo, SQRLStrategy, SQRLStrategyConfig } from '../passport-sqrl';

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
        (clientRequestInfo: SQRLClientRequestInfo, done: any): void => {
          authCalled = true;
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
        (clientRequestInfo: SQRLClientRequestInfo, done: any): void => {
          authCalled = true;
        });

      let url = sqrl.getSqrlUrl(<express.Request> { });
      assert.equal(url, 'sqrl://domain.com/login?nut=nuts!&sfn=ZW5lbXk');

      assert.isFalse(authCalled);
    });
  });
});
