
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
   * Creates a SQRL URL from full "nut" metadata.
   * @param secure Whether the server is using TLS, which maps to the 'sqrl://' or 'qrl://' schemes.
   * @param domain The site domain, e.g. "www.foo.com"
   * @param pathString Optional path string, e.g. "path/to/sqrlLogin". May start with a forward slash.
   * @param serverNut The opaque, unique server data generated for this URL, passed as the nut= query parameter.
   * @param domainExtension When positive, specifies the value to place into the x= query parameter that tells the client how many characters of the pathString to include in its server key hash.
   */
  public static create(
      secure: boolean,
      domain: string,
      pathString: string | null,
      serverNut: string | Buffer,
      domainExtension?: number)
      : string {
    let scheme = secure ? 'sqrl' : 'qrl';

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

    return `${scheme}://${domain}${pathString}?nut=${serverNut}${domainExt}`;
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
   * @param serverNut The opaque, unique server data generated for this URL, passed as the nut= query parameter.
   */
  public createFromNut(serverNut: string | Buffer): string {
    return SqrlUrlFactory.create(this.secure, this.domain, this.pathString, serverNut);
  }

  /**
   * Creates a SQRL URL from the provided unique server data.
   * @param pathString Path string, e.g. "path/to/sqrlLogin". May start with a forward slash.
   * @param serverNut The opaque, unique server data generated for this URL, passed as the nut= query parameter.
   * @param domainExtension When positive, specifies the value to place into the x= query parameter that tells the client how many characters of the pathString to include in its server key hash.
   */
  public createFromPathAndNut(pathString: string, serverNut: string | Buffer, domainExtension?: number): string {
    return SqrlUrlFactory.create(this.secure, this.domain, pathString, serverNut, domainExtension);
  }
}
