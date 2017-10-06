// Unit test suite for SqrlUrl code.

import { assert } from "chai";
import { SqrlUrl, SqrlUrlFactory } from '../passport-sqrl/SqrlUrl';

describe('SqrlUrlFactory', () => {
  describe('StaticUrlCreationChecks', () => {
    it('should return the expected URL format from various parameter configurations passed to SqlUrlFactory.create()', () => {
      let url = SqrlUrlFactory.create(false, 'foo.com', null, "secure1");
      assert.equal(url, 'qrl://foo.com?nut=secure1');

      url = SqrlUrlFactory.create(true, 'www.foo.com', '/sqrlLogin', "secure2");
      assert.equal(url, 'sqrl://www.foo.com/sqrlLogin?nut=secure2');

      url = SqrlUrlFactory.create(true, 'www.foo.com', 'sqrlLogin2?', new Buffer("secure3"));
      assert.equal(url, 'sqrl://www.foo.com/sqrlLogin2?nut=secure3');

      url = SqrlUrlFactory.create(true, 'www.foo.com', '', new Buffer("secure4"));
      assert.equal(url, 'sqrl://www.foo.com?nut=secure4');

      url = SqrlUrlFactory.create(true, 'www.foo.com', '', new Buffer("secure5"), 1);
      assert.equal(url, 'sqrl://www.foo.com?nut=secure5');

      url = SqrlUrlFactory.create(true, 'www.foo.com', 'someuser', new Buffer("secure6"), 1);
      assert.equal(url, 'sqrl://www.foo.com/someuser?nut=secure6&x=1');

      url = SqrlUrlFactory.create(true, 'www.foo.com', 'someuser', new Buffer("secure7"), 1000);
      assert.equal(url, 'sqrl://www.foo.com/someuser?nut=secure7&x=9');

      url = SqrlUrlFactory.create(true, 'www.foo.com', '/someuser?', new Buffer("secure8"), 1000);
      assert.equal(url, 'sqrl://www.foo.com/someuser?nut=secure8&x=9');
    });
  });

  describe('FactoryCreationChecks', () => {
    it('should return the expected URL format from various parameter configurations passed to an instance of SqlUrlFactory', () => {
      let factory = new SqrlUrlFactory(true, 'foo.com', '/sqrlLogin');
      let url = factory.createFromNut("secure1");
      assert.equal(url, 'sqrl://foo.com/sqrlLogin?nut=secure1');

      factory = new SqrlUrlFactory(false, 'foo.com', null);
      url = factory.createFromNut("secure2");
      assert.equal(url, 'qrl://foo.com?nut=secure2');

      url = factory.createFromPathAndNut("/login", "secure2");
      assert.equal(url, 'qrl://foo.com/login?nut=secure2');
    });
  });
});
