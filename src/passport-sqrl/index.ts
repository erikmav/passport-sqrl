// Main Strategy module for passport-sqrl

import base64url from 'base64url';
import * as crypto from 'crypto';
import * as express from 'express';
import { AuthenticateOptions } from 'passport';
import { Strategy } from 'passport-strategy';
import { SqrlBodyParser } from './SqrlBodyParser';
import { SqrlUrlFactory } from './SqrlUrlFactory';

// TODO: Unit test for getting error on incorrect version number
// TODO: Store URLs returned to clients  - or hashes of same - with policies like 12-hour timeouts. Check for valid URLs/hashes on client requests beyond 'query'.
// TODO: Store nuts returned to clients.
// TODO: Add nutCheckCallback: Promise<boolean> with backing in cache-like storage
// TODO: Add urlCheckCallback: Promise<boolean> with backing in cache-like storage
// TODO: Do we allow multiple query calls on URLs? Multiple calls to any URL?
// TODO: Unit test for incorrect client URL - attack by client making things up
// TODO: Unit tests for mising client fields - bad client or attack
// TODO: Support default implementation of encrypted nut and support TIFFlags.IPAddressesMatch

/** Definitions for the Transaction Information Flag values specified in the SQRL specification. */
export enum TIFFlags {
  /** The web server found an identity association for the user based on the primary/current identity key. */
  CurrentIDMatch = 0x01,

  /** The web server found an identity association for the user based on the deprecated/previous identity key. */
  PreviousIDMatch = 0x02,

  /** The IP address seen at the server for this response is the same as the requester IP for the login page. */
  IPAddressesMatch = 0x04,

  /** The user's SQRL profile on the server has previously been marked disabled by the user. */
  IDDisabled = 0x08,

  /** The client's request contained an unknown or unsupported verb. 0x40 CommandFailed will also be set in this case. */
  FunctionNotSupported = 0x10,

  /**
   * The server encountered an internal error and requests that the client reissue its request using the new nut
   * and query information in this response.
   */
  TransientError = 0x20,

  /** The command failed. If 0x80 ClientFailure is not set, this indicates a non-retryable problem at the server. */
  CommandFailed = 0x40,

  /** The command failure was because the client's request was malformed. */
  ClientFailure = 0x80,

  /**
   * The SQRL ID specified in the client's request did not match the SQRL ID in ambient session
   * identity referred to by the client's cookie. The user needs to use the correct SQRL ID or
   * log out of the web site and log back in with a new identity.
   */
  BadIDAssociation = 0x100,
}

/**
 * Returned from a completed AuthCallback promise.
 * Exceptions thrown from the AuthCallback are turned into HTTP 500 errors.
 */
export class AuthCompletionInfo {
  /**
   * When present, indicates authentication success and provides the user record retrieved
   * or created during the authentication request.
   * 
   * This field is not expected to be non-null for a SQRL 'query' command.
   */
  public user?: any;

  /** SQRL Transaction Information Flags to return to the client. */
  public tifValues: TIFFlags;

  /**
   * The client's Session Unlock Key if requested by the client
   * sending a 'suk' option header (ClientRequestInfo.returnSessionUnlockKey)
   */
  public sessionUnlockKey?: string;

  constructor() {
    this.tifValues = 0;
  }
}

/**
 * An authentication callback called from the SQRL passport strategy object.
 * On its returned Promise completion the result is used to feed the response to the caller.
 * @param clientRequestInfo Information parsed and verified from the information provided by the client.
 */
export type AuthCallback = (clientRequestInfo: ClientRequestInfo) => Promise<AuthCompletionInfo>;

/**
 * ExpressJS middleware for the SQRL API.
 * This handler is intended to be attached to a SQRL-specific route, e.g. '/sqrl',
 * that is not hooked into PassportJS.
 * 
 * Experimental - the original implementation for SQRL is in class SQRLStrategy
 * as a PassportJS Strategy, but Strategies do not have access to the 'res'
 * response object and cannot send a response body.
 * 
 */
export class SQRLExpress {
  private config: SQRLStrategyConfig;
  private queryCallback: AuthCallback;
  private identCallback: AuthCallback;
  private disableCallback: AuthCallback;
  private enableCallback: AuthCallback;
  private removeCallback: AuthCallback;
  private urlFactory: SqrlUrlFactory;
  private nutGenerator: (req: express.Request) => string | Buffer;

  /**
   * Creates a new SQRL passport strategy instance.
   * @param authCallback Called by the SQRL strategy to verify access for the provided client key and other information.
   */
  constructor(
      config: SQRLStrategyConfig,
      query: AuthCallback,
      ident: AuthCallback,
      disable: AuthCallback,
      enable: AuthCallback,
      remove: AuthCallback) {
    this.config = config;
    this.queryCallback = query;
    this.identCallback = ident;
    this.disableCallback = disable;
    this.enableCallback = enable;
    this.removeCallback = remove;

    this.urlFactory = new SqrlUrlFactory(
        config.secure,
        config.localDomainName,
        config.port,
        config.urlPath,
        config.domainExtension);

    if (!config.nutGenerator) {
      this.nutGenerator = this.generateRandomNut;
    } else {
      this.nutGenerator = config.nutGenerator;
    }
  }

  /**
   * Composes and returns a SQRL URL containing a unique "nut",
   * plus the nut value for registration for the external
   * phone login flow.
   * 
   * The URL should be passed though a QR-Code generator to
   * produce the SQRL login QR for the client.
   */
  public getSqrlUrl(req: express.Request): SQRLUrlAndNut {
    let nut: string | Buffer = this.nutGenerator(req);
    let nutString = SqrlUrlFactory.nutToString(nut);
    return new SQRLUrlAndNut(this.urlFactory.create(nutString), nut, nutString);
  }

  /**
   * The Express middleware handler. Use like:
   * 
   * let sqrlApi = new SQRLExpress(...);
   * app.post('/sqrl', sqrlApi.HandleSqrlApi);
   */
  public HandleSqrlApi = (req: express.Request, res: express.Response) => {
    // Promisify to allow async coding style in authenticateAync and in unit tests.
    this.authenticateAsync(req)
      .then(authResult => {
        res.write(authResult.body);
        res.statusCode = authResult.httpResponseCode;
        
        // TODO - can we wire this into Passport somehow?
        if (!authResult.callFail) {
          // We have a user. Can we get PassportJS to accept it and perform its normal
          // steps, including various auth success options, translation of session key value,
          // and so on?
        }

        res.end();
      })
      .catch(err => {
        // TODO: Can we differentiate transient versus nontransient errors?
        /* tslint:disable:no-bitwise */
        let tif: TIFFlags = TIFFlags.CommandFailed | TIFFlags.TransientError;
        /* tslint:enable:no-bitwise */

        // Per SQRL protocol, the name-value pairs below will be joined in the same order
        // with CR and LF characters, then base64url encoded.
        let serverLines: string[] = [
          'ver=1',  // Suported versions list
          'nut=' + SqrlUrlFactory.nutToString(this.nutGenerator(req)),  // TODO: Register this with upper handler
          'tif=' + tif.toString(16),
          'qry=' + this.config.urlPath,

          // Use "ask" dialog on client to show error.
          'ask=' + "Server error: " + err.toString(),
        ];
        let resp = serverLines.join("\r\n") + "\r\n";  // Last line must have CRLF as well.
        resp = base64url.encode(resp);

        res.statusCode = 500;
        res.end(resp);
      });
  }

  /**
   * Promisified version of authenticate(), public for unit testing.
   * Not part of the PassportJS API.
   */
  public async authenticateAsync(req: express.Request): Promise<AuthenticateAsyncResult> {
    let params: any;
    if (req.method === "POST") {
      params = req.body;
    } else {
      params = req.params;  // Allow GET calls with URL params.
    }

    let clientRequestInfo: ClientRequestInfo = SqrlBodyParser.parseBodyFields(params);
    if (clientRequestInfo.protocolVersion !== 1) {
      throw new Error(`This server only handles SQRL protocol revision 1`);
    }

    // Fill in the nut and next URL before the callback to let them be stored during the call.
    clientRequestInfo.nextNut = SqrlUrlFactory.nutToString(this.nutGenerator(req));

    let callback: AuthCallback;
    switch (clientRequestInfo.sqrlCommand) {
      case 'query':
        callback = this.queryCallback;
        break;
      case 'ident':
        callback = this.identCallback;
        break;
      case 'disable':
        callback = this.disableCallback;
        break;
      case 'enable':
        callback = this.enableCallback;
        break;
      case 'remove':
        callback = this.removeCallback;
        break;
      default:
        throw new Error(`Unknown SQRL command ${clientRequestInfo.sqrlCommand}`);
    }

    // The await here will throw any exceptions outward to the
    // authenticate() callback handler.
    let authCompletion: AuthCompletionInfo = await callback(clientRequestInfo);
    console.log(`erik: cmd ${clientRequestInfo.sqrlCommand}, user? ${authCompletion.user}`);
    return <AuthenticateAsyncResult> {
      user: authCompletion.user,
      body: this.authCompletionToResponseBody(clientRequestInfo, authCompletion),

      // Per the SQRL API for calls like query we must return a 200 even though
      // there is no login performed, as this is really an API endpoint with multiple
      // round-trips.
      httpResponseCode: 200,

      // Only for the ident API call do we return a success call to Passport,
      // along with the user.
      callFail: (clientRequestInfo.sqrlCommand !== 'ident' || !authCompletion.user)
    };
  }

  /** Default implementation of nut generation - creates a 128-bit random number. */
  private generateRandomNut(): string | Buffer {
    return crypto.randomBytes(16 /*128 bits*/);
  }

  private authCompletionToResponseBody(clientRequestInfo: ClientRequestInfo, authInfo: AuthCompletionInfo): string {
    // Per SQRL protocol, the name-value pairs below will be joined in the same order
    // with CR and LF characters, then base64url encoded.
    let serverLines: string[] = [
      'ver=1',  // Suported versions list
      'nut=' + clientRequestInfo.nextNut,
      'tif=' + (authInfo.tifValues || 0).toString(16),
      'qry=' + this.config.urlPath,
    ];

    if (clientRequestInfo.clientProvidedSession && clientRequestInfo.sqrlCommand !== 'query') {
      serverLines.push('url=' + this.config.clientLoginSuccessUrl);
    }
    if (clientRequestInfo.returnSessionUnlockKey && authInfo.sessionUnlockKey) {
      serverLines.push('suk=' + authInfo.sessionUnlockKey);
    }
    if (this.config.clientCancelAuthUrl) {
      serverLines.push('can=' + this.config.clientCancelAuthUrl);
    }

    let resp = serverLines.join("\r\n") + "\r\n";  // Last line must have CRLF as well.
    resp = base64url.encode(resp);
    return resp;
  }
}

/** The main SQRL PassportJS middleware. */
export class SQRLStrategy extends Strategy {
  /**
   * The strategy name ('sqrl') to use when configuring a passport mapping
   * to an authentication route.
   */
  public name: string = 'sqrl';
  
  private config: SQRLStrategyConfig;
  private queryCallback: AuthCallback;
  private identCallback: AuthCallback;
  private disableCallback: AuthCallback;
  private enableCallback: AuthCallback;
  private removeCallback: AuthCallback;
  private urlFactory: SqrlUrlFactory;
  private nutGenerator: (req: express.Request) => string | Buffer;

  /**
   * Creates a new SQRL passport strategy instance.
   * @param authCallback Called by the SQRL strategy to verify access for the provided client key and other information.
   */
  constructor(
      config: SQRLStrategyConfig,
      query: AuthCallback,
      ident: AuthCallback,
      disable: AuthCallback,
      enable: AuthCallback,
      remove: AuthCallback) {
    super();

    this.config = config;
    this.queryCallback = query;
    this.identCallback = ident;
    this.disableCallback = disable;
    this.enableCallback = enable;
    this.removeCallback = remove;

    this.urlFactory = new SqrlUrlFactory(
        config.secure,
        config.localDomainName,
        config.port,
        config.urlPath,
        config.domainExtension);

    if (!config.nutGenerator) {
      this.nutGenerator = this.generateRandomNut;
    } else {
      this.nutGenerator = config.nutGenerator;
    }
  }

  /**
   * Composes and returns a SQRL URL containing a unique "nut",
   * plus the nut value for registration for the external
   * phone login flow.
   * 
   * The URL should be passed though a QR-Code generator to
   * produce the SQRL login QR for the client.
   */
  public getSqrlUrl(req: express.Request): SQRLUrlAndNut {
    let nut: string | Buffer = this.nutGenerator(req);
    let nutString = SqrlUrlFactory.nutToString(nut);
    return new SQRLUrlAndNut(this.urlFactory.create(nutString), nut, nutString);
  }

  /**
   * PassportJS callback called when this strategy is configured on an HTTP(S)
   * POST route and a client call is received.
   */
  public authenticate(req: express.Request, options?: AuthenticateOptions): void {
    // Promisify to allow async coding style here and in unit tests.
    this.authenticateAsync(req, options)
      .then(authResult => {
        if (authResult.callFail) {
          this.fail(authResult.body, authResult.httpResponseCode);
        } else {
          this.success(authResult.user, authResult.body);
        }
      })
      .catch(err => this.error(err));
  }

  /**
   * Promisified version of authenticate(), public for unit testing.
   * Not part of the PassportJS API.
   */
  public async authenticateAsync(req: express.Request, options?: any): Promise<AuthenticateAsyncResult> {
    let params: any;
    if (req.method === "POST") {
      params = req.body;
    } else {
      params = req.params;  // Allow GET calls with URL params.
    }

    let clientRequestInfo: ClientRequestInfo = SqrlBodyParser.parseBodyFields(params);
    if (clientRequestInfo.protocolVersion !== 1) {
      throw new Error(`This server only handles SQRL protocol revision 1`);
    }

    // Fill in the nut and next URL before the callback to let them be stored during the call.
    clientRequestInfo.nextNut = SqrlUrlFactory.nutToString(this.nutGenerator(req));

    console.log(`erik: choosing from ${clientRequestInfo.sqrlCommand}`);
    let callback: AuthCallback;
    switch (clientRequestInfo.sqrlCommand) {
      case 'query':
        callback = this.queryCallback;
        break;
      case 'ident':
        callback = this.identCallback;
        break;
      case 'disable':
        callback = this.disableCallback;
        break;
      case 'enable':
        callback = this.enableCallback;
        break;
      case 'remove':
        callback = this.removeCallback;
        break;
      default:
        throw new Error(`Unknown SQRL command ${clientRequestInfo.sqrlCommand}`);
    }

    // The await here will throw any exceptions outward to the
    // authenticate() callback handler.
    let authCompletion: AuthCompletionInfo = await callback(clientRequestInfo);
    console.log(`erik: cmd ${clientRequestInfo.sqrlCommand}, user? ${authCompletion.user}`);
    return <AuthenticateAsyncResult> {
      user: authCompletion.user,
      body: this.authCompletionToResponseBody(clientRequestInfo, authCompletion),

      // Per the SQRL API for calls like query we must return a 200 even though
      // there is no login performed, as this is really an API endpoint with multiple
      // round-trips.
      httpResponseCode: 200,

      // Only for the ident API call do we return a success call to Passport,
      // along with the user.
      callFail: (clientRequestInfo.sqrlCommand !== 'ident' || !authCompletion.user)
    };
  }

  /** Default implementation of nut generation - creates a 128-bit random number. */
  private generateRandomNut(): string | Buffer {
    return crypto.randomBytes(16 /*128 bits*/);
  }

  private authCompletionToResponseBody(clientRequestInfo: ClientRequestInfo, authInfo: AuthCompletionInfo): string {
    // Per SQRL protocol, the name-value pairs below will be joined in the same order
    // with CR and LF characters, then base64url encoded.
    let serverLines: string[] = [
      'ver=1',  // Suported versions list
      'nut=' + clientRequestInfo.nextNut,
      'tif=' + (authInfo.tifValues || 0).toString(16),
      'qry=' + this.config.urlPath,
    ];

    if (clientRequestInfo.clientProvidedSession && clientRequestInfo.sqrlCommand !== 'query') {
      serverLines.push('url=' + this.config.clientLoginSuccessUrl);
    }
    if (clientRequestInfo.returnSessionUnlockKey && authInfo.sessionUnlockKey) {
      serverLines.push('suk=' + authInfo.sessionUnlockKey);
    }
    if (this.config.clientCancelAuthUrl) {
      serverLines.push('can=' + this.config.clientCancelAuthUrl);
    }

    let resp = serverLines.join("\r\n") + "\r\n";  // Last line must have CRLF as well.
    resp = base64url.encode(resp);
    return resp;
  }
}

/**
 * Encapsulates the parameters that are needed to resolve a
 * Passport Strategy's authenticate() call.
 * Public for unit testing.
 */
export class AuthenticateAsyncResult {
  /**
   * When user is present, this is optional additional user information, e.g. a profile.
   * When user and err are undefined this should be set to provide information to
   * return to the client in a 401 challenge response; it can be either a string or an object
   * having 'message' and 'type' fields.
   *
   * This field is not expected to be non-null for a SQRL 'query' command.
   */
  public user?: any;

  /** Response body additional information. */
  public body?: any;

  public httpResponseCode: number;

  /**
   * When false, the Passport base success(user, body) is called.
   * When true, Passport base fail(body) is called instead.
   */
  public callFail: boolean;
}

/** A SQRL URL and its contained nut, broken out to separate fields for varying purposes. */
export class SQRLUrlAndNut {
  public url: string;
  public nut: string | Buffer;
  public nutString: string;

  constructor(url: string, nut: string | Buffer, nutString: string) {
    this.url = url;
    this.nut = nut;
    this.nutString = nutString;
  }
}

/**
 * Parameters derived from the POST or GET parameters to the SQRL auth route.
 * This information gets passed to the query, ident, disable, enable, and remove
 * callbacks to the auth implementation. The public keys provided here have
 * already been validated against the private key and the nut and URL signatures.
 *
 * See https://www.grc.com/sqrl/protocol.htm particularly "How to form the POST verb's body."
 */
export class ClientRequestInfo {
  /** The client's SQRL protocol revision. */
  public protocolVersion: number;

  /**
   * The requested SQRL operation. One of the various SQRL client commands
   * (https://www.grc.com/sqrl/semantics.htm):
   *   'query' - initial identity validation to a site, or a later round of attempt to find a previous
   *             identity key that the server recognizes;
   *   'ident' - requests the server to accept the user's identity.
   *   'disable' - requests the server to disable the user's identity, typically for reasons
   *               of potential hacking;
   *   'enable' - reverse of 'disable'
   *   'remove' - requests the server to remove the user's identity (which must have previously been
   *              disabled) from the server's identity store.
   */
  public sqrlCommand: string;
  
  /**
   * The primary identity public key that the client wishes to use to contact this
   * server in the future. It may not correspond to a public key previously received
   * at this server if previously presented - but now deprecated - public keys are
   * presented one per 'query' command in previousIdentityPublicKey.
   * 
   * This value is a SQRL-base64 (base64 minus any tail '=' padding characters) string.
   * Use the primaryIdentityPublicKeyBuf() function to retrieve a Buffer version of this string.
   * 
   * This public key has been successfully validated against the corresponding client-provided
   * signature in the request.
   */
  public primaryIdentityPublicKey: string;

  /**
   * Optional previous identity public key that the client wishes to deprecate
   * in favor of the public key presented in primaryIdentityPublicKey. Typically
   * this value is absent since identity changes are intended to be rare amongst
   * SQRL clients.
   */
  public previousIdentityPublicKey?: string;

  /**
   * The public part of an identity key pair that must be retained by the server and
   * passed back to the client if it needs to perform an identity re-keying operation.
   * 
   * See the server unlock protocol discussion at https://www.grc.com/sqrl/idlock.htm .
   */
  public serverUnlockPublicKey?: string;

  /**
   * The public part of a key that must be retained by the server and used to verify
   * the signature of any possible future Unlock Request.
   * 
   * See the server unlock protocol discussion at https://www.grc.com/sqrl/idlock.htm .
   */
  public serverVerifyUnlockPublicKey?: string;

  /**
   * Optional field sent by the client (in its 'ins=' field) providing
   * a hash of the server-sent value (in the server's 'sin=' field) using
   * the primary identity key.
   */
  public indexSecret?: string;

  /**
   * Optional field sent by the client (in its 'pins=' field) providing
   * a hash of the server-sent value (in the server's 'sin=' field) using
   * the deprecated identity key (if any) specified in this client request's
   * previousIdentityPublicKey ('pidk=') field.
   */
  public previousIndexSecret?: string;
  
  /**
   * Optional flag from the client ('sqrlonly' in its opt= option flag list, see
   * https://www.grc.com/sqrl/semantics.htm) in a non-query command, requesting
   * that the server disable other allowed authentication methods in favor of only SQRL.
   * The server should ignore this field value in query commands.
   */
  public useSqrlIdentityOnly: boolean;

  /**
   * Optional flag from the client ('hardlock' in its opt= option flag list, see
   * https://www.grc.com/sqrl/semantics.htm) in a non-query command, requesting
   * that the server disable security question style alternate identity recovery methods.
   * The server should ignore this field value in query commands.
   */
  public hardLockSqrlUse: boolean;

  /**
   * Optional flag from the client ('cps' in its opt= option flag list, see
   * https://www.grc.com/sqrl/semantics.htm) in an 'ident' command, requesting
   * that the server return in a url= response the logged-in URL that a client-side
   * plugin should redirect to after login is completed.
   */
  public clientProvidedSession: boolean;

  /**
   * Optional flag from the client ('suk' in its opt= option flag list, see
   * https://www.grc.com/sqrl/semantics.htm) in a query command, requesting
   * that the server return its stored Session Unlock Key value to the client
   * so it can issue a re-key request.
   */
  public returnSessionUnlockKey: boolean;

  /**
   * Optional client information (the 'btn=' information field) containing the
   * user's response to a previously presented server "ask" presented to the client.
   * This value, if presemt, is 1, 2, or 3 corresponding the ask selection buttons
   * 1 or 2, or 3 for the question having been dismissed without answering.
   */
  public serverAskResponseSelection?: number;

  /**
   * A new nut that will be returned in the nut= server response.
   * The auth handler should store this nut in its "Recently Issued Nuts"
   * cache to allow responding to NutCheckCallback calls.
   */
  public nextNut: string;

  /** Provides a Buffer version of primaryIdentityPublicKey. */
  public primaryIdentityPublicKeyBuf(): Buffer {
    return Buffer.from(this.primaryIdentityPublicKey, 'base64');
  }
}

/** Provided to the SQRL strategy constructor to provide configuration information. */
export class SQRLStrategyConfig {
  /** Whether the site uses TLS and the 'sqrl://' (as opposed to 'qrl://') URL scheme should be generated. */
  public secure: boolean;

  /** Provides the domain name to use in generating SQRL URLs to send to clients. */
  public localDomainName: string;

  /** The port. If not specified the URL will not include one and the browser will use the appropriate default. */
  public port?: number;

  /**
   * The URL path to the site's login route that receives the SQRL
   * client's HTTP POST, used for generating SQRL URLs. Typically
   * you set this to the same string as the route used to wire up
   * the SQRL passport strategy.
   */
  public urlPath?: string;

  /**
   * The length of the urlPath (including an implicit '/' prefix)
   * that the SQRL client should include in its hash calculations
   * when generating a per-site key pair. This does not need to be
   * specified if the base domain name is sufficient as a site key.
   * It should be specified if the URL path includes a portion
   * that produces the semantics of a separate site, e.g. on GitHub
   * the /username or /username/reponame if a unique key is needed
   * for such paths.
   */
  public domainExtension?: number;

  /**
   * An optional "nut" generator. When undefined, a cryptographically
   * strong random value is generated. When defined,
   * the configured callback can generate any desired "nut" including
   * values from the ExpressJS request (e.g. client IP, datetime, and
   * so on - see the "pre-login state" section at
   * https://www.grc.com/sqrl/server.htm).
   * 
   * When a Buffer is returned, the byte values of the buffer are
   * converted to a base64 string, minus any appended '=' characters,
   * as part of composing the URL.
   */
  public nutGenerator?: (req: express.Request) => string | Buffer;

  /**
   * The URL, typically a relative URL on the site, where the client
   * should redirect on a successful login. This is used in response
   * to SQRL commands other than 'query' that specify the cps
   * (client-provided session) option asking for a success redirect.
   * It is sent to the client in the url= response parameter
   * (see https://www.grc.com/sqrl/semantics.htm).
   */
  public clientLoginSuccessUrl: string;

  /**
   * Optional 302 redirect that a same-device (browser plugin) SQRL
   * client can use to redirect the client if the user cancels
   * the authentication flow. This value is encoded in the can=
   * body field (see https://www.grc.com/sqrl/semantics.htm).
   */
  public clientCancelAuthUrl?: string;
}
