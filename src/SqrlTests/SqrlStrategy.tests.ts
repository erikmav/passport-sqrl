// Unit test suite for SQRLStrategy code.

import { assert } from "chai";
import * as express from 'express';
import { AuthCallback, AuthCompletionInfo, AuthenticateAsyncResult, ClientRequestInfo, SQRLStrategy, SQRLStrategyConfig, TIFFlags, UrlAndNut } from '../passport-sqrl';
import { MockLogger } from '../SqrlTests/MockLogger';
import { MockSQRLClient, ServerResponseInfo } from './MockSqrlClient';

describe('SQRLStrategy', () => {
  describe('strategyName', () => {
    it('should return the expected value for the name field', () => {
      let sqrl = new SQRLStrategy(new MockLogger(), <SQRLStrategyConfig> {
        localDomainName: 'domain.com'
      });

      assert.equal('sqrl', sqrl.name);
    });
  });
});
