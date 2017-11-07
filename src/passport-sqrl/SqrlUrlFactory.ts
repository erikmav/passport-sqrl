import base64url from 'base64url';

/**
 * Converts the bytes in the buffer to base64url and trims trailing '='
 * characters per the SQRL specification.
 */
export function toSqrlBase64(buf: Buffer): string {
  return trimEqualsChars(buf.toString('base64'));
}

/** Trims any tail '=' characters, returning the trimmed string. */
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
