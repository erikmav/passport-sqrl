// Main Strategy module for passport-sqrl

import * as express from 'express';
import { Strategy } from 'passport-strategy';

export class SQRLPassportStrategy extends Strategy {
  public name: string = 'passport-sqrl';

  public authenticate(req: express.Request, options?: any): void {

  }

}
