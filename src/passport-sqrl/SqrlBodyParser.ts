import base64url from 'base64url';
import * as ed25519 from 'ed25519';
import { ClientRequestInfo } from './index';

/** Parses and verifies the various parts of SQRL requests. */
export class SqrlBodyParser {
  /** Reverses base64url encoding then parses the expected CRLF separated fields. */
  public static parseBase64CRLFSeparatedFields(base64Props: string): any {
    // The body is a base64url-encoded string that, when decoded, is a set of
    // name-value pairs separated by CRLF pairs (see https://www.grc.com/sqrl/protocol.htm).
    let preSplit: string = base64url.decode(base64Props);
    let lines: string[] = preSplit.split('\r\n');
    
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
  public static parseBodyFields(body: any): ClientRequestInfo {
    if (!body) {
      throw new Error("Body is required");
    }

    if (!body.client) {
      throw new Error("Body client field is required");
    }
    let clientProps = SqrlBodyParser.parseBase64CRLFSeparatedFields(body.client);
    
    //  server: string,
    //  idSignature: string,
    //  prevIDSignatures?: string[],
    //  unlockRequestSignature?: string): ClientRequestInfo {
    
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
            // TODO: Unknown. Log? Throw?
        }
      });
    }

    return requestInfo;
  }
}
