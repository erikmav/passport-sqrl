// Main Strategy module for passport-sqrl

import * as crypto from 'crypto';
import * as express from 'express';
import { Strategy } from 'passport-strategy';
import { SqrlUrlFactory } from './SqrlUrlFactory';

/**
 * An authentication callback called from the SQRL passport strategy object.
 * @param clientPublicKey A string version of the client's primary public key.
 * @param done This is a Connect callback that should be called on completion of callback handling.
 */
export type AuthCallback = (clientPublicKey: string, done: any) => void;

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
   * Called by the passport middleware when this strategy is configured on an
   * HTTP POST route.
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
    let ids = params.ids;  // 
  }

  private generateRandomNut(): string | Buffer {
    return crypto.randomBytes(16 /*128 bits*/);
  }
}

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
