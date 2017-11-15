import base64url from 'base64url';
import * as ed25519 from 'ed25519';
import * as url from 'url';
import { ClientInputError, ClientRequestInfo } from './index';

/** Parses and verifies the various parts of SQRL requests. */
export class SqrlBodyParser {
  /** Reverses base64url encoding then parses the expected CRLF separated fields. */
  public static parseBase64CRLFSeparatedFields(base64Props: string): any {
    let preSplit: string = base64url.decode(base64Props);
    return SqrlBodyParser.parseCRLFSeparatedFields(preSplit);
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

    let clientProps = SqrlBodyParser.parseBase64CRLFSeparatedFields(params.client);
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
      let qrCodeUrl: url.Url = url.parse(serverDecoded, /*parseQueryString:*/true);
      requestInfo.nut = qrCodeUrl.query.nut;
    } else {
      let serverProps = SqrlBodyParser.parseBase64CRLFSeparatedFields(params.server);
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
