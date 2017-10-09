// Main Strategy module for passport-sqrl

import * as crypto from 'crypto';
import * as express from 'express';
import { Strategy } from 'passport-strategy';
import { SqrlBodyParser } from './SqrlBodyParser';
import { SqrlUrlFactory } from './SqrlUrlFactory';

/** Returned from a completed AuthCallback promise. */
export class AuthCompletionInfo {
  /**
   * When present, indicates an internal error when processing the auth callback.
   * Results in a 500 Server Error HTTP response.
   */
  public err?: Error;

  /**
   * When present, indicates authentication success and provides the user record retrieved
   * or created during the authentication request.
   */
  public user?: any;

  /**
   * When user is present, this is optional additional user information, e.g. a profile.
   * When user and err are undefined this should be set to provide information to
   * return to the client in a 401 challenge response; it can be either a string or an object
   * having 'message' and 'type' fields.
   */
  public info?: any;
}

/**
 * An authentication callback called from the SQRL passport strategy object.
 * On its returned Promise completion the result is used to feed the response to the caller.
 * @param clientRequestInfo Information parsed and verified from the information provided by the client.
 */
export type AuthCallback = (clientRequestInfo: ClientRequestInfo) => Promise<AuthCompletionInfo>;

/** The main SQRL passport middleware. */
export class SQRLStrategy extends Strategy {
  /**
   * The strategy name ('sqrl') to use when configuring a passport mapping
   * to an authentication route.
   */
  public name: string = 'sqrl';
  
  private config: SQRLStrategyConfig;
  private authCallback: AuthCallback;
  private urlFactory: SqrlUrlFactory;
  private nutGenerator: (req: express.Request) => string | Buffer;

  /**
   * Creates a new SQRL passport strategy instance.
   * @param authCallback Called by the SQRL strategy to verify access for the provided client key and other information.
   */
  constructor(config: SQRLStrategyConfig, authCallback: AuthCallback) {
    super();

    if (!config) {
      throw new Error("Parameter 'config' must be provided");
    }

    this.config = config;
    this.authCallback = authCallback;
    this.urlFactory = new SqrlUrlFactory(
        config.secure,
        config.localDomainName,
        config.urlPath,
        config.domainExtension,
        config.serverFriendlyName);

    if (!config.nutGenerator) {
      this.nutGenerator = this.generateRandomNut;
    } else {
      this.nutGenerator = config.nutGenerator;
    }
  }

  /**
   * Composes and returns a SQRL URL containing a unique "nut".
   * This URL should be passed though a QR-Code generator to
   * produce the SQRL login QR for the client.
   */
  public getSqrlUrl(req: express.Request): string {
    return this.urlFactory.create(this.nutGenerator(req));
  }

  /**
   * Called by the PassportJS middleware when this strategy is configured on an
   * HTTP POST route and a client call is received.
   */
  public authenticate(req: express.Request, options?: any): void {
    let params: any;
    if (req.method === "POST") {
      params = req.body;
    } else {
      params = req.params;  // Allow GET calls with URL params.
    }

    // Expected params from https://www.grc.com/sqrl/protocol.htm "POST Queries" section.
    let client = params.client;  // base64url encoded client arguments consisting of name1=value1&name2=value2&... format
    let server = params.server;  // base64url encoded original SQRL URL, or base64url encoded name1=value1&name2=value2&... format
    let ids = params.ids;

    let clientRequestInfo: ClientRequestInfo = SqrlBodyParser.parseBodyParts(
        client,
        server,
        ids,
        undefined /*TODO*/,
        undefined/*TODO*/);

    this.authCallback(clientRequestInfo)
        .then((authCompletion: AuthCompletionInfo) => {
          console.log('erik: authCallback completed');
          if (authCompletion.err) {
            this.error(authCompletion.err);
          } else if (!authCompletion.user) {
            this.fail(authCompletion.info);
          } else {
            this.success(authCompletion.user, authCompletion.info);
          }
        })
        .catch((reason: any) => this.error(reason));

    // Note on return here the asynchronous callback+promise above may not have returned.
    // We can't perform an await here as this is not an async function.
    // (Important for unit testing - have to poll for the end result or timeout.)
    // In PassportJS and Connect+Express, the eventual call to this.success()/fail()/error()
    // causes a response on the web site.
  }

  /** Default implementation of nut generation - creates a 128-bit random number. */
  private generateRandomNut(): string | Buffer {
    return crypto.randomBytes(16 /*128 bits*/);
  }
}

/**
 * Parameters derived from the POST or GET parameters to the SQRL auth route.
 * See https://www.grc.com/sqrl/protocol.htm particularly "How to form the POST verb's body."
 */
export class ClientRequestInfo {
  /** The requested SQRL operation. */
  public sqrlCommand: string;
  
  /**
   * The primary identity public key that the client wishes to use to contact this
   * server in the future. It may not correspond to a public key previously received
   * at this server if previously presented - but now deprecated - public keys are
   * presented in previousIdentotyPublicKey.
   * 
   * This value is a SQRL-base64 (base64 minus any tail '=' padding characters) string.
   * Use the primaryIdentityPublicKeyBuf() function to retrieve a Buffer version of this string.
   * 
   * This public key has been successfully validated against the corresponding client-provided
   * signature in the request.
   */
  public primaryIdentityPublicKey: string;

  /**
   * Zero or more previous identity public keys that the client wishes to deprecate
   * in favor of the public key presented in primaryIdentityPublicKey. This
   * array my be undefined or have zero entries (which is the typical case
   * since identity changes are intended to be rare amongst SQRL clients).
   */
  public previousIdentityPublicKeys: string[] | undefined;

  /**
   * The public part of an identity key pair that must be retained by the server and
   * passed back to the client if it needs to perform an identity re-keying operation.
   * 
   * See the server unlock protocol discussion at https://www.grc.com/sqrl/idlock.htm .
   */
  public serverUnlockPublicKey: string;

  /**
   * The public part of a key that must be retained by the server and used to verify
   * the signature of any possible future Unlock Request.
   * 
   * See the server unlock protocol discussion at https://www.grc.com/sqrl/idlock.htm .
   */
  public serverVerifyUnlockPublicKey: string;

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
   * Optional server friendly name for display in the SQRL client.
   * This value maps to the sfn= query parameter on generated SQRL URLs.
   */
  public serverFriendlyName?: string;

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
}
