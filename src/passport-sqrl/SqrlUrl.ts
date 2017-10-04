
/**
 * Implements a SQRL URL generator and parser.
 * Based on https://www.grc.com/sqrl/protocol.htm
 * Unit tests are in SqrlUrl.tests.ts.
 */
export class SqrlUrl {
  constructor(url: string) {

  }
}

/**
 * Creates SQRL URLs. The static methods may be used directly, or else an instance
 * of this class may be instantiated with configuration information to reduce
 * the number of parameters a caller has to pass.
 */
export class SqrlUrlFactory {
  /**
   * Creates a SQRL URL from full metadata.
   * @param secure Whether the server is using TLS, which maps to the 'sqrl://' or 'qrl://' schemes.
   * @param domain The site domain, e.g. "www.foo.com"
   * @param pathString Optional path string, e.g. "path/to/sqrlLogin". May start with a forward slash.
   * @param serverData The opaque, unique server data generated for this URL.
   */
  public static create(secure: boolean, domain: string, pathString: string | null, serverData: string | Buffer): string {
    let scheme = secure ? 'sqrl' : 'qrl';

    if (!pathString) {
      pathString = '';
    }

    if (pathString.length > 0 && pathString[0] !== '/') {
      pathString = '/' + pathString;
    }

    if (pathString.length === 0 || pathString[pathString.length - 1] !== '?') {
      pathString = pathString + '?';
    }

    return `${scheme}://${domain}${pathString}${serverData}`;
  }

  private secure: boolean;
  private domain: string;
  private pathString: string | null;
  
  /**
   * Creates a SQRL URL factory with static configuration information.
   * @param secure Whether the server is using TLS, which maps to the 'sqrl://' or 'qrl://' schemes.
   * @param domain The site domain, e.g. "www.foo.com"
   * @param pathString Optional path string, e.g. "path/to/sqrlLogin". May start with a forward slash.
   */
  constructor(secure: boolean, domain: string, pathString: string | null) {
    this.secure = secure;
    this.domain = domain;
    this.pathString = pathString;
  }

  /**
   * Creates a SQRL URL from the provided unique server data.
   * @param serverData The opaque, unique server data generated for this URL.
   */
  public create(serverData: string | Buffer): string {
    return SqrlUrlFactory.create(this.secure, this.domain, this.pathString, serverData);
  }
}
