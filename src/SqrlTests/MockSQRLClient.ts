import base64url from 'base64url';
import { assert } from "chai";
import * as crypto from 'crypto';
import * as ed25519 from 'ed25519';
import * as url from 'url';

/**
 * Implements the logic for a minimal SQRL client, used for generating mock call data for unit tests
 * or real calls to a loopback NodeJS server hosting the passport-sqrl auth strategy.
 */
export class MockSQRLClient {
  public static canonicalizeSqrlUrl(sqrlUrl: string): string {
    // Disassemble the SQRL URL and reassemble with only canonical parts.
    // See https://www.grc.com/sqrl/protocol.htm "What we use, what we ignore.
    let urlObj: url.Url = url.parse(sqrlUrl, /*parseQueryString:*/false);
    let scheme = (urlObj.protocol || '').toLowerCase();  // Already has ':' suffix
    let domain = (urlObj.hostname || '').toLowerCase();
    let path = urlObj.path ? urlObj.path : '';  // With parseQueryString==false this is the full path and query string after the hostname
    return `${scheme}//${domain}${path}`;
  }

  private canonicalizedSqrlUrl: string;
  private originalSqrlUrl: string;
  private primaryIdentityPublicKey: Buffer;
  private primaryIdentityPrivateKey: Buffer;

  constructor(sqrlUrl: string) {
    this.originalSqrlUrl = sqrlUrl;
    this.canonicalizedSqrlUrl = MockSQRLClient.canonicalizeSqrlUrl(sqrlUrl);

    // Generate Ed25519 keypair for the primary identity.
    let seed: Buffer = crypto.randomBytes(32);
    let keyPair = ed25519.MakeKeypair(seed);
    this.primaryIdentityPublicKey = keyPair.publicKey;
    this.primaryIdentityPrivateKey = keyPair.privateKey;
  }

  /**
   * Generates a POST body as a set of name-value pairs (i.e. pre-base64url encoding for transmission).
   * @param cmd: One of the various SQRL client commands (https://www.grc.com/sqrl/semantics.htm):
   *   'query' - initial identity validation to a site, or a later round of attempt to find a previous
   *             identity key that the server recognizes;
   *   'ident' - requests the server to accept the user's identity.
   *   'disable' - requests the server to disable the user's identity, typically for reasons
   *               of potential hacking;
   *   'enable' - reverse of 'disable'
   *   'remove' - requests the server to remove the user's identity (which must have previously been
   *              disabled) from the server's identity store.
   * @param options: A tilde (~) separated set of option flags for the server. E.g. 
   */
  public generatePostBody(cmd: string, options?: string): any {
    // Per SQRL client value protocol, the name-value pairs below will be joined in the same order
    // with CR and LF characters, then base64url encoded.
    let clientLines: string[] = [
      'ver=1',
      `cmd=${cmd}`,
      'idk=' + base64url.encode(this.primaryIdentityPublicKey)
      // TODO: Add deprecated key(s), Server Unlock Key, and cases for Server Verify Unlock key
    ];

    if (options) {
      clientLines.push(`opt=${options}`);
    }

    let client = clientLines.join('\r\n');
    let server = base64url.encode(this.originalSqrlUrl);
    let clientServer = new Buffer(client + server, 'utf8');
    let clientServerSignature = ed25519.Sign(clientServer, this.primaryIdentityPrivateKey);

    return {
      client: base64url.encode(client),
      server: base64url.encode(server),
      ids: base64url.encode(clientServerSignature)
      // TODO: Add more fields like pids, urs
    };
  }
}

describe('SQRLClient', () => {
  describe('canonicalizePreCanonicalized', () => {
    it('should generate the same canonicalized URLs', () => {
      let testUrls: string[] = [
        'qrl://foo.com',
        'qrl://foo.com/bar?blah=boo',
        'sqrl://foo.com?bar=blah',
      ];

      testUrls.forEach(testUrl =>
        assert.equal(MockSQRLClient.canonicalizeSqrlUrl(testUrl), testUrl, testUrl));
    });
  });

  describe('canonicalizeNonCanonicalized', () => {
    it('should generate proper canonicalized URLs', () => {
      assert.equal(MockSQRLClient.canonicalizeSqrlUrl('qrl://user:pass@www.foo.com'), 'qrl://www.foo.com');
      assert.equal(MockSQRLClient.canonicalizeSqrlUrl('sqrl://foo.com:12345'), 'sqrl://foo.com');
      assert.equal(MockSQRLClient.canonicalizeSqrlUrl('sqrl://foo.com:12345/path?query=1'), 'sqrl://foo.com/path?query=1');
      assert.equal(MockSQRLClient.canonicalizeSqrlUrl('SQrL://FOO.com:12345/Path?query=UPPERCASE'), 'sqrl://foo.com/Path?query=UPPERCASE');
    });
  });
});
