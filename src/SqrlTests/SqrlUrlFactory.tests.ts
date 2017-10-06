// Unit test suite for SqrlUrlFactory code.

import { assert } from "chai";
import { SqrlUrlFactory } from '../passport-sqrl/SqrlUrlFactory';

describe('SqrlUrlFactory', () => {
  describe('StaticUrlCreationChecks', () => {
    it('should return the expected URL format from various parameter configurations passed to SqlUrlFactory.create()', () => {
      let url = SqrlUrlFactory.create(false, 'foo.com', "secure1");
      assert.equal(url, 'qrl://foo.com?nut=secure1');

      url = SqrlUrlFactory.create(true, 'www.foo.com', "secure2", '/sqrlLogin');
      assert.equal(url, 'sqrl://www.foo.com/sqrlLogin?nut=secure2');

      url = SqrlUrlFactory.create(true, 'www.foo.com', new Buffer("secure3"), 'sqrlLogin2?');
      assert.equal(url, 'sqrl://www.foo.com/sqrlLogin2?nut=secure3');

      url = SqrlUrlFactory.create(true, 'www.foo.com', new Buffer("secure4"), '');
      assert.equal(url, 'sqrl://www.foo.com?nut=secure4');

      url = SqrlUrlFactory.create(true, 'www.foo.com', new Buffer("secure5"), '', 1);
      assert.equal(url, 'sqrl://www.foo.com?nut=secure5');

      url = SqrlUrlFactory.create(true, 'www.foo.com', new Buffer("secure6"), 'someuser', 1);
      assert.equal(url, 'sqrl://www.foo.com/someuser?nut=secure6&x=1');

      url = SqrlUrlFactory.create(true, 'www.foo.com', new Buffer("secure7"), 'someuser', 1000);
      assert.equal(url, 'sqrl://www.foo.com/someuser?nut=secure7&x=9');

      url = SqrlUrlFactory.create(true, 'www.foo.com', new Buffer("secure8"), '/someuser?', 1000);
      assert.equal(url, 'sqrl://www.foo.com/someuser?nut=secure8&x=9');

      url = SqrlUrlFactory.create(true, 'www.foo.com', new Buffer("secure9"), /*path*/undefined, /*domainExt*/undefined, "Foo");
      assert.equal(url, 'sqrl://www.foo.com?nut=secure9&sfn=Rm9v');
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

      factory = new SqrlUrlFactory(true, 'foo.com', '/login', "Friendly!");
      url = factory.create("secure4");
      assert.equal(url, 'sqrl://foo.com/login?nut=secure4&sfn=RnJpZW5kbHkh');
    });
  });
});
