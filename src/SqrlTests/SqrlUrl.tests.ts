// Unit test suite for SqrlUrl code.

import { assert } from "chai";
import { SqrlUrl, SqrlUrlFactory } from '../passport-sqrl/SqrlUrl';

describe('SqrlUrlFactory', () => {
  describe('StaticUrlCreationChecks', () => {
    it('should return the expected URL format from various parameter configurations passed to SqlUrlFactory.create()', () => {
      let url = SqrlUrlFactory.create(false, 'foo.com', null, "secure1");
      assert.equal(url, 'qrl://foo.com?secure1');

      url = SqrlUrlFactory.create(true, 'www.foo.com', '/sqrlLogin', "secure2");
      assert.equal(url, 'sqrl://www.foo.com/sqrlLogin?secure2');

      url = SqrlUrlFactory.create(true, 'www.foo.com', 'sqrlLogin2?', new Buffer("secure3"));
      assert.equal(url, 'sqrl://www.foo.com/sqrlLogin2?secure3');

      url = SqrlUrlFactory.create(true, 'www.foo.com', '', new Buffer("secure4"));
      assert.equal(url, 'sqrl://www.foo.com?secure4');
    });
  });

  describe('FactoryCreationChecks', () => {
    it('should return the expected URL format from various parameter configurations passed to an instance of SqlUrlFactory', () => {
      let factory = new SqrlUrlFactory(true, 'foo.com', '/sqrlLogin');
      let url = factory.create("secure1");
      assert.equal(url, 'sqrl://foo.com/sqrlLogin?secure1');

      factory = new SqrlUrlFactory(false, 'foo.com', null);
      url = factory.create("secure2");
      assert.equal(url, 'qrl://foo.com?secure2');
    });
  });
});
