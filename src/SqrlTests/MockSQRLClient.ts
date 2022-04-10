import base64url from 'base64url';
import { assert } from "chai";
import * as crypto from 'crypto';
import * as ed25519 from 'ed25519';
import * as fs from 'fs';
import * as requestPromise from 'request-promise-native';
import * as url from 'url';
import { BodyParser, ClientRequestInfo, TIFFlags } from '../passport-sqrl';

const serverTlsCertDir = __dirname;
const serverTlsCaChain = serverTlsCertDir + "/TestSite.FullChain.Cert.pem";

/**
 * Implements the logic for a minimal SQRL client, used for generating mock call data for unit tests
 * or real calls to a loopback or remote NodeJS server hosting the passport-sqrl auth strategy.
 * This client object contains protocol state for the conversation with the web server.
 * One client object is required for each server and, depending on its state, for each
 * interaction with the server.
 */
export class MockSQRLClient {
  public static canonicalizeSqrlUrl(sqrlUrl: string): string {
    // Disassemble the SQRL URL and reassemble with only canonical parts.
    // See https://www.grc.com/sqrl/protocol.htm "What we use, what we ignore."
    let urlObj: url.Url = url.parse(sqrlUrl, /*parseQueryString:*/false);
    let scheme = (urlObj.protocol || '').toLowerCase();  // Already has ':' suffix
    let domain = (urlObj.hostname || '').toLowerCase();
    let path = urlObj.path ? urlObj.path : '';  // With parseQueryString==false this is the full path and query string after the hostname
    return `${scheme}//${domain}${path}`;
  }

  public static generateServerContactUrl(sqrlUrl: string): string {
    // Disassemble the SQRL URL and reassemble with callable HTTP scheme/protocol.
    let urlObj: url.Url = url.parse(sqrlUrl, /*parseQueryString:*/false);
    let path = urlObj.path ? urlObj.path : '';  // With parseQueryString==false this is the full path and query string after the hostname
    let port = urlObj.port ? ':' + urlObj.port : '';
    return `https://${urlObj.hostname}${port}${path}`;
  }

  // Options flags that get sent to the server on each request.
  public useSqrlIdentityOnly: boolean = false;
  public hardLockSqrlUse: boolean = false;
  public clientProvidedSession: boolean = false;
  public returnSessionUnlockKey: boolean = false;

  public canonicalizedSqrlUrl: string;
  public serverContactUrl: string;
  public originalSqrlUrl: string;
  public primaryIdentityPublicKey: Buffer;
  public previousIdentityPublicKeys: Buffer[] = [];
  public lastQueryPrevIdTried: number = -1;
  public serverReturnedSessionUnlockKey: Buffer | undefined;

  // Malformed request injection flags
  public omitVersion: boolean = false;
  public omitCommand: boolean = false;
  public omitIDKey: boolean = false;
  public omitPrimarySignature: boolean = false;
  public omitClient: boolean = false;
  public omitServer: boolean = false;
  
  private primaryIdentityPrivateKey: Buffer;
  private previousIdentityPrivateKeys: Buffer[] = [];
  private certValidationList: Buffer[];
  private sqrlVersion: number;
  
  constructor(sqrlUrl: string, numPreviousIdentities: number = 0, sqrlVersion: number = 1) {
    this.originalSqrlUrl = sqrlUrl;
    this.sqrlVersion = sqrlVersion;
    this.canonicalizedSqrlUrl = MockSQRLClient.canonicalizeSqrlUrl(sqrlUrl);
    this.serverContactUrl = MockSQRLClient.generateServerContactUrl(sqrlUrl);

    // Generate Ed25519 keypair for the primary identity.
    let seed: Buffer = crypto.randomBytes(32);
    let keyPair = ed25519.MakeKeypair(seed);
    this.primaryIdentityPublicKey = keyPair.publicKey;
    this.primaryIdentityPrivateKey = keyPair.privateKey;

    // Generate additional keys for the previous identities if any.
    for (let i = 0; i < numPreviousIdentities; i++) {
      seed = crypto.randomBytes(32);
      keyPair = ed25519.MakeKeypair(seed);
      this.previousIdentityPublicKeys.push(keyPair.publicKey);
      this.previousIdentityPrivateKeys.push(keyPair.privateKey);
    }

    // Set up TLS acceptance list for the cert chain on the test site.
    // http://www.benjiegillam.com/2012/06/node-dot-js-ssl-certificate-chain/
    let testSiteCertChain = fs.readFileSync(serverTlsCaChain);
    this.certValidationList = [ testSiteCertChain ];
  }

  /** Performs an HTTP(S) call to a server. */
  public async performInitialQuery(): Promise<ServerResponseInfo> {
    let postBody: RequestPostBody = this.generatePostBody('query');
    let reqOptions = <requestPromise.RequestPromiseOptions> {
      ca: this.certValidationList,
      agentOptions: {
        ca: this.certValidationList
      },
      rejectUnauthorized: false,

      method: 'POST',
      form: postBody
    };

    console.log(`MockSQRLClient: Running query against ${this.serverContactUrl}`);
    let resBody: string = await requestPromise(this.serverContactUrl, reqOptions);
    let res: ServerResponseInfo = this.parseServerBody(resBody);
    return res;
  }

  /**
   * Generates a POST body as a set of name-value pairs (i.e. pre-base64url encoding for transmission).
   * Public for unit testing but intended for internal use.
   * @param cmd: One of the various SQRL client commands (https://www.grc.com/sqrl/semantics.htm):
   *   'query' - initial identity validation to a site, or a later round of attempt to find a previous
   *             identity key that the server recognizes;
   *   'ident' - requests the server to accept the user's identity.
   *   'disable' - requests the server to disable the user's identity, typically for reasons
   *               of potential hacking;
   *   'enable' - reverse of 'disable'
   *   'remove' - requests the server to remove the user's identity (which must have previously been
   *              disabled) from the server's identity store.
   * @param primaryIdentOnly: Forces the client to present only its primary identity even
   * if there are deprecated secondary identities. Default is to use everything available. 
   */
  public generatePostBody(cmd: string, primaryIdentOnly: boolean = false): RequestPostBody {
    // Per SQRL client value protocol, the name-value pairs below will be joined in the same order
    // with CR and LF characters, then base64url encoded.
    let clientLines: string[] = [];

    if (!this.omitVersion) {
      clientLines.push(`ver=${this.sqrlVersion}`);
    }
    if (!this.omitCommand) {
      clientLines.push(`cmd=${cmd}`);
    }
    if (!this.omitIDKey) {
      clientLines.push('idk=' + base64url.encode(this.primaryIdentityPublicKey));
    }
    // TODO: Add Server Unlock Key, and cases for Server Verify Unlock key

    if (!primaryIdentOnly && this.previousIdentityPublicKeys.length > 0) {
      this.lastQueryPrevIdTried = (this.lastQueryPrevIdTried + 1) % this.previousIdentityPublicKeys.length;
      clientLines.push('pidk=' + base64url.encode(this.previousIdentityPublicKeys[this.lastQueryPrevIdTried]));
    }

    let options: string[] = [];
    if (this.useSqrlIdentityOnly) {
      options.push('sqrlonly');
    }
    if (this.hardLockSqrlUse) {
      options.push('hardlock');
    }
    if (this.clientProvidedSession) {
      options.push('cps');
    }
    if (this.returnSessionUnlockKey) {
      options.push('suk');
    }
    if (options.length) {
      let opt = options.join('~');
      clientLines.push(`opt=${opt}`);
    }

    let clientPreBase64 = clientLines.join('\r\n') + '\r\n';  // SQRL spec requires trailing CRLF
    let client = base64url.encode(clientPreBase64);
    let server = base64url.encode(this.originalSqrlUrl);  // TODO: Use previous reply info on 2nd and later round trips
    let clientServer = Buffer.from(client + server, 'utf8');
    let clientServerSignature = ed25519.Sign(clientServer, this.primaryIdentityPrivateKey);

    let result = <RequestPostBody> {
      client: this.omitClient ? undefined : client,
      server: this.omitServer ? undefined : server,
      ids: this.omitPrimarySignature ? undefined : base64url.encode(clientServerSignature),
    };

    if (!primaryIdentOnly && this.previousIdentityPublicKeys.length > 0) {
      let prevSignature = ed25519.Sign(clientServer, this.previousIdentityPrivateKeys[this.lastQueryPrevIdTried]);
      result.pids = base64url.encode(prevSignature);
    }
    // TODO: Add urs field
    return result;
  }

  /**
   * Parses a response budy and updates local client state to
   * prepare the client for the next call.
   */
  public parseServerBody(body: string): ServerResponseInfo {
    let props = BodyParser.parseBase64CRLFSeparatedFields(body);

    let vers: string[] = props.ver.split(',');
    let supportedVersions: number[] = [];
    vers.forEach(ver => {
      let rangeLoHi: string[] = ver.split('-');
      if (rangeLoHi.length === 1) {
        supportedVersions.push(Number(rangeLoHi[0]));
      } else if (rangeLoHi.length === 2) {
        let lo = Number(rangeLoHi[0]);
        let hi = Number(rangeLoHi[1]);
        for (let i = lo; i <= hi; i++) {
          supportedVersions.push(i);
        }
      } else {
        throw new Error(`Version value ${ver} appears to be malformed, with either no values or more than one dash`);
      }
    });

    if (!props.nut) {
      throw new Error('Server values did not contain the required nut= property');
    }
    if (!props.tif) {
      throw new Error('Server values did not contain the required tif= property');
    }
    if (!props.qry) {
      throw new Error('Server values did not contain the required qry= property');
    }

    let askMessage: string | undefined;
    let askButton1Label: string | undefined;
    let askButton1Url: string | undefined;
    let askButton2Label: string | undefined;
    let askButton2Url: string | undefined;
    if (props.ask) {
      let parts: string[] = props.ask.split('~');
      askMessage = parts[0];
      let button1Parts = parts[1].split(';');
      askButton1Label = button1Parts[0];
      if (button1Parts.length > 1) {
        askButton1Url = button1Parts[1];
      }
      if (parts.length > 2) {
        let button2Parts = parts[2].split(';');
        askButton2Label = button2Parts[0];
        if (button2Parts.length > 1) {
          askButton2Url = button2Parts[1];
        }
      }
    }

    return <ServerResponseInfo> {
      supportedProtocolVersions: supportedVersions,
      nextNut: props.nut,
      tifValues: parseInt(props.tif, 16),
      nextRequestPathAndQuery: props.qry,
      successfulAuthenticationRedirectUrl: props.url,
      secretIndex: props.sin,
      serverUnlockKey: props.suk,
      askMessage: askMessage,
      askButton1Label: askButton1Label,
      askButton1Url: askButton1Url,
      askButton2Label: askButton2Label,
      askButton2Url: askButton2Url      
    };
  }
}

/** The POST request body fields sent by the client to the server. Field names are defined by the SQRL standard. */
export class RequestPostBody {
  public client?: string;
  public server?: string;
  public ids?: string;
  public pids?: string;
  public urs?: string;
}

export class ServerResponseInfo {
  /** The SQRL protocol version numbers supported by the server. */
  public supportedProtocolVersions: number[] = [];

  /** The server nut value that the client should use in its next call to the server. */
  public nextNut?: string;

  /** Exposes a numeric value for the TIF flags. */
  public tifValues: TIFFlags = 0;

  /** The new URL path and query string to be used in the next contact with the server. */
  public nextRequestPathAndQuery?: string;

  /**
   * When the client included its 'cps' (client-provided session) flag, this specifies the
   * redirect URL the user should be directed to on successful login. Corresponds to the
   * server's 'url=' response field.
   */
  public successfulAuthenticationRedirectUrl?: string;

  /**
   * A redirect URL the user should be directed to on a canceled login. Corresponds to the
   * server's 'can=' response field.
   */
  public canceledAuthenticationRedirectUrl?: string;

  /**
   * An optional server request for the this value (as binary) to be hashed using the client's
   * identity and returned in the next request.
   */
  public secretIndex?: string;

  /**
   * The server unlock key originally registered with the server. Returned if the client requested
   * the server unlock key to be returned in a query command (using its 'suk' option flag).
   */
  public serverUnlockKey?: string;

  /** Server-requested text for the main message of a dialog request to the user. */
  public askMessage?: string;

  /** Server-requested text for button 1 of a dialog request to the user. */
  public askButton1Label?: string;

  /** Server-provided response URL if the user taps button 1 of a dialog request to the user. */
  public askButton1Url?: string;

  /** Server-requested text for button 2 of a dialog request to the user. */
  public askButton2Label?: string;

  /** Server-provided response URL if the user taps button 2 of a dialog request to the user. */
  public askButton2Url?: string;
}

//
// Unit tests
//

describe('SQRLClient', () => {
  describe('canonicalizePreCanonicalized', () => {
    it('should generate the same canonicalized URLs', () => {
      let testUrls: string[] = [
        'sqrl://foo.com',
        'sqrl://foo.com/bar?blah=boo',
        'sqrl://foo.com?bar=blah',
      ];

      testUrls.forEach(testUrl =>
        assert.equal(MockSQRLClient.canonicalizeSqrlUrl(testUrl), testUrl, testUrl));
    });
  });

  describe('canonicalizeNonCanonicalized', () => {
    it('should generate proper canonicalized URLs', () => {
      assert.equal(MockSQRLClient.canonicalizeSqrlUrl('sqrl://user:pass@www.foo.com'), 'sqrl://www.foo.com');
      assert.equal(MockSQRLClient.canonicalizeSqrlUrl('sqrl://foo.com:12345'), 'sqrl://foo.com');
      assert.equal(MockSQRLClient.canonicalizeSqrlUrl('sqrl://foo.com:12345/path?query=1'), 'sqrl://foo.com/path?query=1');
      assert.equal(MockSQRLClient.canonicalizeSqrlUrl('SQrL://FOO.com:12345/Path?query=UPPERCASE'), 'sqrl://foo.com/Path?query=UPPERCASE');
    });
  });

  describe('generateServerContactUrl', () => {
    it('should generate proper contact URLs', () => {
      assert.equal(MockSQRLClient.generateServerContactUrl('sqrl://user:pass@www.foo.com'), 'https://www.foo.com');
      assert.equal(MockSQRLClient.generateServerContactUrl('sqrl://foo.com:12345'), 'https://foo.com:12345');
      assert.equal(MockSQRLClient.generateServerContactUrl('sqrl://foo.com:12345/path?query=1'), 'https://foo.com:12345/path?query=1');
      assert.equal(MockSQRLClient.generateServerContactUrl('SQrL://FOO.com:12345/Path?query=UPPERCASE'), 'https://foo.com:12345/Path?query=UPPERCASE');
    });
  });

  describe('genAndParseClient', () => {
    it('should be able to generate and parse the client body to the same result', () => {
      let mockClient = new MockSQRLClient('sqrl://foo.com/login?nut=1234', /*numPreviousIdentities:*/1);
      mockClient.useSqrlIdentityOnly = true;
      mockClient.hardLockSqrlUse = true;
      mockClient.clientProvidedSession = true;
      mockClient.returnSessionUnlockKey = true;
      let bodyFields: any = mockClient.generatePostBody('query');
      assert.isFalse(!bodyFields.client);
      assert.isFalse(!bodyFields.server);

      let clientRequestInfo: ClientRequestInfo = BodyParser.parseAndValidateRequestFields(bodyFields);

      assert.equal('query', clientRequestInfo.sqrlCommand);
      // TODO: Check other fields
      assert.isTrue(clientRequestInfo.useSqrlIdentityOnly);
      assert.isTrue(clientRequestInfo.hardLockSqrlUse);
      assert.isTrue(clientRequestInfo.clientProvidedSession);
      assert.isTrue(clientRequestInfo.returnSessionUnlockKey);
      assert.equal('1234', clientRequestInfo.nut);
    });
  });
});
