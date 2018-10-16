// Main module for passport-sqrl

import base64url from 'base64url';
import * as crypto from 'crypto';
import * as ed25519 from 'ed25519';
import * as express from 'express';
import { AuthenticateOptions } from 'passport';
import { Strategy } from 'passport-strategy';
import * as urlLib from 'url';

// TODO: Support default implementation of encrypted nut and support TIFFlags.IPAddressesMatch
// TODO: Support disable, enable, remove
// TODO: Support suk client request and server validation
// TODO: Add urs= field
// TODO: Add UT for rekey request
// TODO: Test rekey against SQRL desktop implementation

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
 * Returned from a completed ISQRLIdentityStorage function promise.
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
 * Log levels for ILogger.
 */
export enum LogLevel { Error, Warning, Info, Debug, Finest }

/**
 * A simple logging interface accepted by the SQRL Strategy.
 * Callers can choose the adapt this call interface to Bunyan or any other logger.
 */
export interface ILogger {
  /**
   * Gets or sets the current log level.
   * When the configured log level is greater than or equal to the level of a specific log trace
   * it is emitted to the log destination.
   */
  logLevel: LogLevel;
  
  error(message: string): void;
  warning(message: string): void;
  info(message: string): void;
  debug(message: string): void;

  /** Finest logging is almost always off in production; use generator to avoid excessive GC. */
  finest(messageGenerator: () => string): void;
}

/**
 * The behavior that must be implemented by the next-higher layer that provides
 * identity storage.
 */
export interface ISQRLIdentityStorage {
  /**
   * Stores a nut issued to a client, along with an optional reference to a
   * predecessor nut value originally presented in a QR code to a user.
   * (If the nut is for an original QR code, originalLoginNut will be undefined
   * or null.)
   * 
   * When we issue a SQRL URL, the nut (and the URL itself) act as a one-time nonce
   * for that specific client. Use of HTTPS for the site prevents disclosure to
   * a man-in-the-middle. There are two important user use cases:
   * 
   * 1. Login is performed in a browser with SQRL browser plugin. The plugin will
   *    specify the cps option to the SQRL API, which means the plugin acts as
   *    a go-between, sending the client's public key and signed SQRL URL, and
   *    on 200 Success it uses the cps response as a success redirect. In this
   *    case, the full query is handled by the plugin.
   * 
   * 2. Login is performed by a separate desktop app or a phone app against the
   *    QR-Code of the URL. The SQRL app contacts the SQRL API and presents the
   *    client's public key and signed SQRL URL, but (usually) without the cps
   *    option, as the app cannot redirect the browser. For this case, a typical
   *    site implementation is to track recent nut values and have a logon page
   *    poll an ajax REST endpoint seeing if the nut was logged in. In that case
   *    the site logs the browser on using an explicit PassportJS res.login()
   *    call to return the user profile reference in the site cookie. See the
   *    /pollNut route in the demo site in the passport-sqrl repo.
   * 
   * Because the SQRL API typically involves multiple round trips to the server
   * (or server cluster behind a VIP) and does not fit within the single round
   * trip authentication model used by PassportJS, tracking recent nuts and their
   * lineage back to a QR code is needed to allow mapping of presented nut
   * values to final logins.
   * 
   * The implementation should store this information in a rapid, distributed
   * lookup storage system like a cache layer (e.g. Redis), with a limited
   * time-to-live value (e.g. 12 hours) after which the nut is forgotten.
   * It should also store any known user profile references along with this
   * information. For a sample implementation see the in-memory NeDB
   * implementation in the demo site in the pasport-sqrl Git repo.
   */
  nutIssuedToClientAsync(urlAndNut: UrlAndNut, originalLoginNut?: string): Promise<void>;

  /**
   * Retrieves stored information about a nut value.
   * See comments on nutIssuedToClientAsync() for more details.
   */
  getNutInfoAsync(nut: string): Promise<NutInfo | null>;

  /**
   * Called on a SQRL client call to verify access, once the client message
   * signature(s) have been validated.
   * 
   * A typical storage schema uses the ClientRequestInfo.primaryIdentityPublicKey
   * as a primary key for reference. However, ClientRequestInfo.previousIdentityPublicKey,
   * if present, may contain an old public key that the user is seeking to change,
   * and the storage layer needs to check that key against its public key index as well.
   * 
   * This method should not create or update any new user records, just return
   * whether the storage layer knows about the user's identity keys by setting
   * AuthCompletionInfo.tifValues. If the primaryIdentityPublicKey matches a
   * known user record, set TIFFlags.CurrentIDMatch; if the primary identity
   * key is unknown but a user record exists under the previousIdentityPublicKey,
   * set TIFFlags.PreviousIDMatch.
   * 
   * If the user profile has previously been disabled, no record updates should be
   * performed and TIFFlags.IDDisabled should be set in AuthCompletionInfo.tifValues.
   */
  queryAsync(clientRequestInfo: ClientRequestInfo, nutInfo: NutInfo): Promise<AuthCompletionInfo>;

  /**
   * Called on a SQRL client call to log in, once the client message
   * signature(s) have been validated.
   * 
   * If the user is not previously known under ClientRequestInfo.primaryIdentityPublicKey
   * or ClientRequestInfo.previousIdentityPublicKey, a new user record should be created.
   * 
   * If a record already exists under previousIdentityPublicKey, this is a re-keying
   * request and the primary public key for the user should be updated to the new
   * primaryIdentityPublicKey.
   * 
   * This method should act in an idempotent manner with respect to login:
   * it should allow multiple ident calls without error. This case is common
   * in the case of client retries over a flaky network.
   * 
   * Any SQRL options specified in this request, such as useSqrlIdentityOnly or
   * hardLockSqrlUse, should be updated in the user record as well, if the site honors
   * these flags.
   * 
   * If the user profile has previously been disabled, no record updates should be
   * performed and TIFFlags.IDDisabled should be set in AuthCompletionInfo.tifValues.
   */
  identAsync(clientRequestInfo: ClientRequestInfo, nutInfo: NutInfo): Promise<AuthCompletionInfo>;

  /**
   * Called on a SQRL client call to disable a SQRL identity, once the client message
   * signature(s) have been validated. The affected identity can be the one referred
   * to by either ClientRequestInfo.primaryIdentityPublicKey or
   * ClientRequestInfo.previousIdentityPublicKey.
   * 
   * This method should act in an idempotent manner with respect to disabling:
   * it should allow multiple disable calls without error. This case is common
   * in the case of client retries over a flaky network.
   */
  disableAsync(clientRequestInfo: ClientRequestInfo, nutInfo: NutInfo): Promise<AuthCompletionInfo>;

  /**
   * Called on a SQRL client call to enable a SQRL identity that was previously
   * disabled, once the client message signature(s) have been validated.
   * 
   * This method should act in an idempotent manner with respect to enabling:
   * it should allow multiple enable calls without error, e.g. if the account is
   * not disbled it should simply take no action on the user record.
   * This case is common in the case of client retries over a flaky network.
   */
  enableAsync(clientRequestInfo: ClientRequestInfo, nutInfo: NutInfo): Promise<AuthCompletionInfo>;

  /**
   * Called on a SQRL client call to remove a SQRL identity, once the client message
   * signature(s) have been validated. The storage layer should delete (or,
   * depending on site schema and old record storage model, mark as hidden)
   * the related user record and prevent future logins using the primary and,
   * if specified, previous identity public keys presented.
   */
  removeAsync(clientRequestInfo: ClientRequestInfo, nutInfo: NutInfo): Promise<AuthCompletionInfo>;
}

/**
 * ExpressJS middleware for the SQRL API.
 * Because SQRL does not use the HTTP Authenticate header in its data flow,
 * this handler is intended to be attached to a SQRL-specific route, e.g. '/sqrl',
 * that is not hooked into PassportJS. See the sample site in the passport-sqrl repo.
 */
export class SQRLExpress {
  private identityStorage: ISQRLIdentityStorage;
  private log: ILogger;
  private config: SQRLStrategyConfig;
  private urlFactory: SqrlUrlFactory;
  private nutGenerator: (req: express.Request) => string | Buffer;

  /**
   * Creates a new SQRL passport strategy instance.
   * @param identityStorage: Provides an identity storage implementation for calls from the SQRL layer.
   * @param log ILogger implementation for logging output. Allowed to be undefined/null.
   *   Errors are used for true errors in execution. Warnings are used for recoverable
   *   issues, e.g. errors caused by data from the network. Debug is for moderate
   *   frequency operational output. Finest is used for intensive traffic logging and
   *   detailed flow output.
   * @param config Configuration settings for this instance.
   */
  constructor(
      identityStorage: ISQRLIdentityStorage,
      log: ILogger,
      config: SQRLStrategyConfig) {
    this.identityStorage = identityStorage;
    this.log = log;
    this.config = config;

    this.urlFactory = new SqrlUrlFactory(
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
   * Composes and returns a SQRL URL containing a unique "nut", plus the nut value for
   * registration for the external app login flow. The URL should be passed though a
   * QR-Code generator to produce the SQRL login QR for the client.
   */
  public getSqrlUrl(req: express.Request): UrlAndNut {
    let nut: string | Buffer = this.nutGenerator(req);
    let nutString = SqrlUrlFactory.nutToString(nut);
    return new UrlAndNut(this.urlFactory.create(nutString), nut, nutString);
  }

  /**
   * The Express middleware handler. Use like:
   * 
   * let sqrlApi = new SQRLExpress(...);
   * app.post('/sqrl', sqrlApi.handleSqrlApi);
   */
  public handleSqrlApi = (req: express.Request, res: express.Response) => {
    // Promisify to allow async coding style in authenticateAync and in unit tests.
    this.authenticateAsync(req)
      .then((authResult: AuthenticateAsyncResult) => {
        this.log.debug('SQRL API call complete: ' +
          `httpResponseCode: ${authResult.httpResponseCode}; ` +
          `user: ${this.objToString(authResult.user)}; ` +
          `encoded body: ${authResult.body}`);
        res.statusCode = authResult.httpResponseCode;
        res.send(authResult.body);
      })
      .catch(e => {
        let err = <ClientInputError> e;  // Cast to commonly thrown error - if not correct, its httpStatusCode will be undefined.
        this.log.error(`Error thrown from SQRL API call: ${err} httpStatusCode=${err.httpStatusCode}`);

        // tslint:disable-next-line:no-bitwise
        let tif: TIFFlags = TIFFlags.CommandFailed | TIFFlags.TransientError;

        // Per SQRL protocol, the name-value pairs below will be joined in the same order
        // with CR and LF characters, then base64url encoded.
        let nextNut = SqrlUrlFactory.nutToString(this.nutGenerator(req));
        let serverLines: string[] = [
          'ver=1',  // Suported versions list
          'nut=' + nextNut,  // TODO: Register this with upper handler
          'tif=' + tif.toString(16),
          'qry=' + this.config.urlPath + '?nut=' + nextNut,

          // Use "ask" dialog on client to show error.
          'ask=' + "Server error: " + err ? err.toString() : "<none>",
        ];
        let resp = serverLines.join("\r\n") + "\r\n";  // Last line must have CRLF as well.
        resp = base64url.encode(resp);

        res.statusCode = err.httpStatusCode || 500;
        res.send(resp);
      });
  }

  /**
   * Promisified version of authenticate(). Not part of the public API.
   */
  protected async authenticateAsync(req: express.Request): Promise<AuthenticateAsyncResult> {
    let params: any;
    if (req.method === "POST") {
      params = req.body;
    } else {
      params = req.params;  // Allow GET calls with URL params.
    }

    let clientRequestInfo: ClientRequestInfo = BodyParser.parseAndValidateRequestFields(params);
    if (clientRequestInfo.protocolVersion !== 1) {
      throw new ClientInputError(`This server only handles SQRL protocol revision 1`);
    }
    let nutInfoPromise: Promise<NutInfo | null> = clientRequestInfo.nut ?
        this.identityStorage.getNutInfoAsync(clientRequestInfo.nut) : Promise.resolve(null);

    let nextNut: string | Buffer = this.nutGenerator(req);
    let nextNutStr = SqrlUrlFactory.nutToString(nextNut);
    let nextUrl = this.config.urlPath + '?nut=' + nextNutStr;
    let urlAndNut = new UrlAndNut(nextUrl, nextNut, nextNutStr);

    let nutInfo: NutInfo | null = await nutInfoPromise;
    if (!nutInfo) {
      throw new ClientInputError('Client presented unknown nut value');
    }

    await this.identityStorage.nutIssuedToClientAsync(urlAndNut, nutInfo.originalLoginNut || nutInfo.nut);
    clientRequestInfo.nextNut = nextNutStr;
    clientRequestInfo.nextUrl = nextUrl;

    this.log.debug(
        `SQRL API call received to ${this.config.urlPath}: ` +
        `HTTP method ${req.method}. Parameter fields:${this.objToString(params)} . ` +
        'Decoded:' + this.objToString(clientRequestInfo));

    // The awaits here will throw any exceptions outward to the
    // authenticate() callback handler.
    let authCompletion: AuthCompletionInfo;
    switch (clientRequestInfo.sqrlCommand) {
      case 'query':
        authCompletion = await this.identityStorage.queryAsync(clientRequestInfo, nutInfo);
        break;
      case 'ident':
        authCompletion = await this.identityStorage.identAsync(clientRequestInfo, nutInfo);
        break;
      case 'disable':
        authCompletion = await this.identityStorage.disableAsync(clientRequestInfo, nutInfo);
        break;
      case 'enable':
        authCompletion = await this.identityStorage.enableAsync(clientRequestInfo, nutInfo);
        break;
      case 'remove':
        authCompletion = await this.identityStorage.removeAsync(clientRequestInfo, nutInfo);
        break;
      default:
        throw new ClientInputError(`Unknown SQRL command ${clientRequestInfo.sqrlCommand}`);
    }

    this.log.debug(`Auth completion info: ${this.objToString(authCompletion)}`);
    return <AuthenticateAsyncResult> {
      user: authCompletion.user,
      body: this.authCompletionToResponseBody(clientRequestInfo, authCompletion),

      // Per the SQRL API for calls like query we must return a 200 even if
      // there is no login performed, as this is really an API endpoint with multiple
      // round-trips, and most of the error information is contained within the
      // SQRL response fields (e.g. TIF).
      httpResponseCode: 200,
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
      'ver=1',  // Supported versions list
      'nut=' + clientRequestInfo.nextNut,
      'tif=' + (authInfo.tifValues || 0).toString(16),
      'qry=' + this.config.urlPath + '?nut=' + clientRequestInfo.nextNut,
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
    this.log.debug(`Response body pre-encoding: ${resp}`);
    resp = base64url.encode(resp);
    return resp;
  }

  private objToString(o: any): string {
    if (!o) {
      return "undefined";
    }
    let values = "";
    for (let propName in o) {
      values += ` ${propName}=${o[propName]}`;
    }
    return values;
  }
}

/**
 * SQRL Strategy for PassportJS.
 */
export class SQRLStrategy extends Strategy {
  /**
   * The strategy name ('sqrl') to use when configuring a passport mapping
   * to an authentication route.
   */
  public name: string = 'sqrl';

  private log: ILogger;
  private config: SQRLStrategyConfig;

  constructor(log: ILogger, config: SQRLStrategyConfig) {
    super();
    this.log = log;
    this.config = config;
  }

  // Currently no additional logic here on top of a basic PassportJS Strategy.
  // SQRL does not use the HTTP Authenticate header and does not present its
  // credentials inline with regular page requests. However, configuration of
  // PassportJS and this (empty) Strategy enables the req.login() method which
  // can be used to wire up detection of a successful login with returning
  // a user profile reference in the ambient site cookie once the SQRL API
  // (see SQRLExpress) has gotten a succesful 'ident' call. For an example
  // of how to do this, see the test site code in TestSiteHandler.ts in
  // the passport-sqrl repo.
}

/**
 * Encapsulates the parameters that are needed to resolve a SQRL API call.
 * Exported for unit testing but not intended to be used directly.
 */
export class AuthenticateAsyncResult {
  /**
   * The user profile for return to PassportJS.
   * This field is expected to be null for a SQRL 'query' command.
   */
  public user?: any;

  /** base64url encoded response fields for return in the API response body. */
  public body?: string;

  public httpResponseCode: number = 500;
}

/** A SQRL URL and its contained nut, broken out to separate fields for varying purposes. */
export class UrlAndNut {
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
  public protocolVersion: number = 1;

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
  public sqrlCommand?: string;

  /**
   * The nut value presented to the server. This could come from an original
   * QR code URL on a first SQRL 'query' command, or a follow-up URL handed
   * back to the client on a query or other response.
   * 
   * Typically this value is used (a) as a layer of security to verify that
   * the client is not just making up random plausible nut values but in fact
   * is returning a nut generated by this server (or server cluster), and (b)
   * to provide a chain of nut values leading from a QR code to an eventual
   * login, for supporting auto-login flows. See doc comments on
   * ISQRLIdentityStorage nutIssuedToClientAsync() and getNutInfoAsync().
   */
  public nut?: string;

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
  public primaryIdentityPublicKey?: string;

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
  public useSqrlIdentityOnly: boolean = false;

  /**
   * Optional flag from the client ('hardlock' in its opt= option flag list, see
   * https://www.grc.com/sqrl/semantics.htm) in a non-query command, requesting
   * that the server disable security question style alternate identity recovery methods.
   * The server should ignore this field value in query commands.
   */
  public hardLockSqrlUse: boolean = false;

  /**
   * Optional flag from the client ('cps' in its opt= option flag list, see
   * https://www.grc.com/sqrl/semantics.htm) in an 'ident' command, requesting
   * that the server return in a url= response the logged-in URL that a client-side
   * plugin should redirect to after login is completed.
   */
  public clientProvidedSession: boolean = false;

  /**
   * Optional flag from the client ('suk' in its opt= option flag list, see
   * https://www.grc.com/sqrl/semantics.htm) in a query command, requesting
   * that the server return its stored Session Unlock Key value to the client
   * so it can issue a re-key request.
   */
  public returnSessionUnlockKey: boolean = false;

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
  public nextNut?: string;

  /**
   * The relative URL to be passed back in the qry= server response field for
   * the next communication from the client.
   */
  public nextUrl?: string;

  /** Provides a Buffer version of primaryIdentityPublicKey. */
  public primaryIdentityPublicKeyBuf(): Buffer | null {
    if (this.primaryIdentityPublicKey) {
      return Buffer.from(this.primaryIdentityPublicKey, 'base64');
    }
    return null;
  }
}

/** Provided to the SQRL strategy constructor to provide configuration information. */
export class SQRLStrategyConfig {
  /** Provides the domain name to use in generating SQRL URLs to send to clients. */
  public localDomainName: string = 'please-configure-me.com';

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
  public clientLoginSuccessUrl?: string;

  /**
   * Optional 302 redirect that a same-device (browser plugin) SQRL
   * client can use to redirect the client if the user cancels
   * the authentication flow. This value is encoded in the can=
   * body field (see https://www.grc.com/sqrl/semantics.htm).
   */
  public clientCancelAuthUrl?: string;
}

/** Data class containing information about a nut from identity storage. */
export class NutInfo {
  /** The unique nut nonce generated and sent to a client. */
  public nut?: string;
  
  /** The nut value from an original QR code, for backtracking from this later nut. */
  public originalLoginNut?: string;
}

/** Error subclass that adds an HTTP status code. */
export class ClientInputError extends Error {
  public httpStatusCode: number;

  constructor(message: string, httpStatusCode: number = 400) {
    super(message);
    this.httpStatusCode = httpStatusCode;
  }
}

/** Parses and verifies the various parts of SQRL requests. Public for unit testing. */
export class BodyParser {
  /** Reverses base64url encoding then parses the expected CRLF separated fields. */
  public static parseBase64CRLFSeparatedFields(base64Props: string): any {
    let preSplit: string = base64url.decode(base64Props);
    return BodyParser.parseCRLFSeparatedFields(preSplit);
  }

  public static parseCRLFSeparatedFields(preSplitLines: string): any {
    // The body is a base64url-encoded string that, when decoded, is a set of
    // name-value pairs separated by CRLF pairs (see https://www.grc.com/sqrl/protocol.htm).
    let lines: string[] = preSplitLines.split('\r\n');
    
    let props: any = {};
    lines.forEach(line => {
      line = line.trim();
      if (line.length === 0) {
        return;
      }
      // The name is considered everything up to the first = sign; the value everything after.
      let eqIndex = line.indexOf('=');
      if (eqIndex < 1) {
        throw new Error(`Failure parsing response line - no equal sign found in: ${line}`);
      }
      let name = line.substring(0, eqIndex);
      let val = line.substring(eqIndex + 1);
      props[name] = val;
    });
    return props;    
  }

  /**
   * Parses the various POST body or GET URL parameter components passed from a SQRL client,
   * and validates that the client-provided signatures match.
   * 
   * The fields can include (from the SQRL spec):
   * client: The 'client' string provided by the client, containing a
   *   base64url-encoded set of name-value pairs.
   * server: The 'server' string provided by the client, either a base64url form of a
   *   SQRL URL presented to the client, or the base64url-encoded body of a response
   *   from a previous API call.
   * idSignature The 'ids' string provided by the client, containing a base64url encoding of
   *   the 512-bit signature of the UTF-8 concatenation of the client and server strings, signed using the
   *   primary identity private key of the client for this server's domain.
   * prevIDSignatures Zero or more 'pids' string(s) provided by the client containing base64url encoded
   *   512-bit signatures of the UTF-8 concatenation of the client and server strings, signed using the
   *   corresponding private keys of the deprecated "previous IDs."
   * unlockRequestSignature An optional 'urs' string provided by the client, containing a base64url
   *   encoding of the 512-bit signature of the UTF-8 concatenation of the client and server strings,
   *   signed using the private Unlock Request Signing Key. The web server uses this The presence of this field and the corresponding
   */
  public static parseAndValidateRequestFields(params: any): ClientRequestInfo {
    if (!params) {
      throw new ClientInputError("Body is required");
    }
    if (!params.client) {
      throw new ClientInputError("Client field is required");
    }
    if (!params.server) {
      throw new ClientInputError("Server field is required");
    }

    let clientProps = BodyParser.parseBase64CRLFSeparatedFields(params.client);
    let requestInfo = <ClientRequestInfo> {
      protocolVersion: Number(clientProps.ver),
      sqrlCommand: clientProps.cmd,
      primaryIdentityPublicKey: clientProps.idk,
      previousIdentityPublicKey: clientProps.pidk,
      serverUnlockPublicKey: clientProps.suk,
      serverVerifyUnlockPublicKey: clientProps.vuk,
      indexSecret: clientProps.ins,
      previousIndexSecret: clientProps.pins,
    };
    if (!requestInfo.primaryIdentityPublicKey) {
      throw new ClientInputError('Missing primary identity public key field in SQRL request');
    }
    if (!params.ids) {
      throw new ClientInputError('Missing ids= primary key signature field in SQRL request');
    }

    // Verify the client's primary and optional previous signatures versus the
    // client+server combined data.
    let clientServer = Buffer.from(params.client + params.server, 'utf8');
    let primaryKeySignature = Buffer.from(params.ids, 'base64');
    let primaryPublicKey = Buffer.from(requestInfo.primaryIdentityPublicKey, 'base64');
    let primaryOK = ed25519.Verify(clientServer, primaryKeySignature, primaryPublicKey);
    if (!primaryOK) {
      throw new ClientInputError('Primary public key did not verify correctly');
    }
    let previousOK = true;
    if (requestInfo.previousIdentityPublicKey) {
      if (!params.pids) {
        throw new ClientInputError('Missing pids= previous key signature field where the pidk= previous public key is specified');
      }
      let previousKeySignature = Buffer.from(params.pids, 'base64');
      let previousPublicKey = Buffer.from(requestInfo.previousIdentityPublicKey, 'base64');
      previousOK = ed25519.Verify(clientServer, previousKeySignature, previousPublicKey);
      if (!previousOK) {
        throw new ClientInputError('Previous public key did not verify correctly');
      }
    }

    // Decode the server= fields and verify a nut is present, and promote into the result.
    let serverDecoded = base64url.decode(params.server);
    if (serverDecoded.startsWith('sqrl')) {
      let qrCodeUrl: urlLib.Url = urlLib.parse(serverDecoded, /*parseQueryString:*/true);
      requestInfo.nut = qrCodeUrl.query && typeof qrCodeUrl.query !== 'string' && qrCodeUrl.query.nut ? qrCodeUrl.query.nut.toString() : undefined;
    } else {
      let serverProps = BodyParser.parseBase64CRLFSeparatedFields(params.server);
      requestInfo.nut = serverProps.nut;
    }
    if (!requestInfo.nut) {
      throw new ClientInputError('server= info from client is not either a QR-code URL with nut= query param or a server response with nut= field');
    }

    if (clientProps.opt) {
      let optFields: string[] = clientProps.opt.toString().split('~');
      optFields.forEach(opt => {
        switch (opt) {
          case 'sqrlonly':
            requestInfo.useSqrlIdentityOnly = true;
            break;
          case 'hardlock':
            requestInfo.hardLockSqrlUse = true;
            break;
          case 'cps':
            requestInfo.clientProvidedSession = true;
            break;
          case 'suk':
            requestInfo.returnSessionUnlockKey = true;
            break;
          default:
            throw new ClientInputError(`Unknown SQRL client option ${opt}`);
        }
      });
    }

    return requestInfo;
  }
}

/**
 * Converts the bytes in the buffer to base64url and trims trailing '='
 * characters per the SQRL specification. Public for unit testing.
 */
export function toSqrlBase64(buf: Buffer): string {
  return trimEqualsChars(base64url.encode(buf));
}

/** Trims any tail '=' characters, returning the trimmed string. Public for unit testing. */
export function trimEqualsChars(s: string): string {
  // Avoid regular expressions - low performance.
  let len = s.length;
  if (!s || len === 0) {
    return s;
  }

  let i = len - 1;
  while (i >= 0) {
    if (s[i] === '=') {
      i--;
    } else {
      break;
    }
  }

  return s.substring(0, i + 1);
}

/**
 * Creates SQRL URLs. The static methods may be used directly, or else an instance
 * of this class may be instantiated with configuration information to reduce
 * the number of parameters a caller has to pass.
 */
export class SqrlUrlFactory {
  /**
   * Creates a SQRL URL from full "nut" metadata.
   * @param domain The site domain, e.g. "www.foo.com"
   * @param serverNut The opaque, unique server data generated for this URL, passed as the nut= query parameter.
   * @param pathString Optional path string, e.g. "path/to/sqrlLogin". May start with a forward slash.
   * @param domainExtension When positive, specifies the value to place into the x= query parameter that tells the client how many characters of the pathString to include in its server key hash.
   */
  public static create(
      domain: string,
      serverNut: string | Buffer,
      port?: number,
      pathString?: string,
      domainExtension?: number)
      : string {
    let portPart = port ? `:${port}` : '';

    if (!pathString) {
      pathString = '';
    }

    if (pathString.length > 0 && pathString[0] !== '/') {
      pathString = '/' + pathString;
    }

    if (pathString.endsWith('?')) {
      pathString = pathString.substring(0, pathString.length - 1);
    }

    // domainExt includes the starting / of the path; start calculating after pathString has that prefix.
    let domainExt = '';
    if (pathString.length > 0 && domainExtension && domainExtension > 0) {
      domainExtension = Math.min(domainExtension, pathString.length);
      domainExt = `&x=${domainExtension}`;
    }

    let nut: string = SqrlUrlFactory.nutToString(serverNut);

    return `sqrl://${domain}${portPart}${pathString}?nut=${nut}${domainExt}`;
  }

  public static nutToString(nut: string | Buffer): string {
    let nutStr: string;
    if (nut instanceof Buffer) {
      nutStr = toSqrlBase64(nut);
    } else {
      nutStr = nut;
    }
    return nutStr;    
  }

  private domain: string;
  private port: number | undefined;
  private pathString: string | undefined;
  private domainExtension?: number;
  
  /**
   * Creates a SQRL URL factory with static configuration information.
   * @param domain The site domain, e.g. "www.foo.com"
   * @param port Optional port.
   * @param pathString Optional path string, e.g. "path/to/sqrlLogin". May start with a forward slash.
   * @param domainExtension When positive, specifies the value to place into the x= query parameter
   *   that tells the client how many characters of the pathString to include in its server key hash.
   */
  constructor(domain: string, port?: number, pathString?: string, domainExtension?: number) {
    this.domain = domain;
    this.port = port;
    this.pathString = pathString;
    this.domainExtension = domainExtension;
  }

  /**
   * Creates a SQRL URL from the provided unique server data.
   * @param serverNut The opaque, unique server data generated for this URL, passed as the nut= query parameter.
   * @param pathString Optional path string, e.g. "path/to/sqrlLogin". May start with a forward slash.
   *   Overrides any path specified in the constructor.
   * @param domainExtension When positive, specifies the value to place into the x= query parameter
   *   that tells the client how many characters of the pathString to include in its server key hash.
   *   Overrides any value specified in the constructor.
   */
  public create(serverNut: string | Buffer, pathString?: string, domainExtension?: number): string {
    return SqrlUrlFactory.create(
        this.domain,
        serverNut,
        this.port,
        pathString || this.pathString,
        domainExtension || this.domainExtension);
  }
}
