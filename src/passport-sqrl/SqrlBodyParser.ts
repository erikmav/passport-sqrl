import { ClientRequestInfo } from './index';

/** Parses and verifies the various parts of SQRL requests. */
export class SqrlBodyParser {
  
  /**
   * Parses the various POST body or GET URL parameter components passed from a SQRL client.
   * @param client The 'client' string provided by the client, containing various ampersand-delimited name-value pairs.
   * @param server The 'server' string provided by the client, either a base64url form of the SQRL URL,
   *   or base64url encoded ampersand-separated name-value pair set previously retrieved from this server/cluster.
   * @param idSignature The 'ids' string provided by the client, containing a base64url encoding of
   *   the 512-bit signature of the UTF-8 concatenation of the client and server strings, signed using the
   *   primary identity private key of the client for this server's domain.
   * @param prevIDSignatures Zero or more 'pids' string(s) provided by the client containing base64url encoded
   *   512-bit signatures of the UTF-8 concatenation of the client and server strings, signed using the
   *   corresponding private keys of the deprecated "previous IDs."
   * @param unlockRequestSignature An optional 'urs' string provided by the client, containing a base64url
   *   encoding of the 512-bit signature of the UTF-8 concatenation of the client and server strings,
   *   signed using the private Unlock Request Signing Key. The web server uses this The presence of this field and the corresponding
   *   
   */
  public static parseBodyParts(
      client: string,
      server: string,
      idSignature: string,
      prevIDSignatures?: string[],
      unlockRequestSignature?: string): ClientRequestInfo {
    
    return <ClientRequestInfo> {
      
    };
  }
}
