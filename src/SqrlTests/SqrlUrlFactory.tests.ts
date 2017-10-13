// Unit test suite for SqrlUrlFactory code.

import { assert } from "chai";
import { SqrlUrlFactory, toSqrlBase64, trimEqualsChars } from '../passport-sqrl/SqrlUrlFactory';

describe('SqrlUrlFactory', () => {
  describe('StaticUrlCreationChecks', () => {
    it('should return the expected URL format from various parameter configurations passed to SqlUrlFactory.create()', () => {
      let url = SqrlUrlFactory.create(false, 'foo.com', "secure1");
      assert.equal(url, 'qrl://foo.com?nut=secure1');

      url = SqrlUrlFactory.create(true, 'www.foo.com', "secure2", '/sqrlLogin');
      assert.equal(url, 'sqrl://www.foo.com/sqrlLogin?nut=secure2');

      url = SqrlUrlFactory.create(true, 'www.foo.com', new Buffer("secure3"), 'sqrlLogin2?');
      assert.equal(url, 'sqrl://www.foo.com/sqrlLogin2?nut=c2VjdXJlMw');

      url = SqrlUrlFactory.create(true, 'www.foo.com', "secure4", '');
      assert.equal(url, 'sqrl://www.foo.com?nut=secure4');

      url = SqrlUrlFactory.create(true, 'www.foo.com', "secure5", '', 1);
      assert.equal(url, 'sqrl://www.foo.com?nut=secure5');

      url = SqrlUrlFactory.create(true, 'www.foo.com', "secure6", 'someuser', 1);
      assert.equal(url, 'sqrl://www.foo.com/someuser?nut=secure6&x=1');

      url = SqrlUrlFactory.create(true, 'www.foo.com', "secure7", 'someuser', 1000);
      assert.equal(url, 'sqrl://www.foo.com/someuser?nut=secure7&x=9');

      url = SqrlUrlFactory.create(true, 'www.foo.com', "secure8", '/someuser?', 1000);
      assert.equal(url, 'sqrl://www.foo.com/someuser?nut=secure8&x=9');

      url = SqrlUrlFactory.create(true, 'www.foo.com', "secure9", /*path*/undefined, /*domainExt*/undefined);
      assert.equal(url, 'sqrl://www.foo.com?nut=secure9');
    });
  });

  describe('FactoryCreationChecks', () => {
    it('should return the expected URL format from various parameter configurations passed to an instance of SqlUrlFactory', () => {
      let factory = new SqrlUrlFactory(true, 'foo.com', '/sqrlLogin');
      let url = factory.create("secure1");
      assert.equal(url, 'sqrl://foo.com/sqrlLogin?nut=secure1');

      factory = new SqrlUrlFactory(false, 'foo.com');
      url = factory.create("secure2");
      assert.equal(url, 'qrl://foo.com?nut=secure2');

      url = factory.create("secure3", "/login");
      assert.equal(url, 'qrl://foo.com/login?nut=secure3');

      factory = new SqrlUrlFactory(true, 'foo.com', '/login', 6);
      url = factory.create("secure4");
      assert.equal(url, 'sqrl://foo.com/login?nut=secure4&x=6');
    });
  });
});

describe('trimEqualsChars', () => {
  describe('trimEqualsCharsCases', () => {
    it('should return the appropriate result strings for various inputs to trimEqualsChars', () => {
      let s = trimEqualsChars('');
      assert.equal(s, '');

      s = trimEqualsChars('=');
      assert.equal(s, '');

      s = trimEqualsChars('====');
      assert.equal(s, '');

      s = trimEqualsChars('abc');
      assert.equal(s, 'abc');

      s = trimEqualsChars('==abc==de');
      assert.equal(s, '==abc==de');

      s = trimEqualsChars('abc==');
      assert.equal(s, 'abc');
    });
  });
});

describe('toSqrlBase64', () => {
  describe('toSqrlBase64Cases', () => {
    it('should return the appropriate result = trimmed base64url strings for various inputs to toSqrlBase64', () => {
      let s = toSqrlBase64(new Buffer([0, 1, 2, 3]));
      assert.equal(s, 'AAECAw');  // Regular base64 encding is 'AAAECAw=='

      s = toSqrlBase64(new Buffer([0, 1, 2, 3, 4, 5]));
      assert.equal(s, 'AAECAwQF');  // Even multiple of 6 bits for encoding, base64 string same as trimmed result.
    });
  });
});
