// Logging interface, with implementations typically defined in
// specific component implementations to match local requirements.

import * as bunyan from 'bunyan';
import { ILogger, LogLevel } from '../passport-sqrl';

export class BunyanLogger implements ILogger {
  public bunyanLogger: bunyan;

  public get logLevel() { return this.logLevelBacking; }
  public set logLevel(lev: LogLevel) {
    let bunyanLevel: number;
    switch (lev) {
      case LogLevel.Error:
        bunyanLevel = bunyan.ERROR;
        break;
      case LogLevel.Warning:
        bunyanLevel = bunyan.WARN;
        break;
      case LogLevel.Info:
        bunyanLevel = bunyan.INFO;
        break;
      case LogLevel.Debug:
        bunyanLevel = bunyan.DEBUG;
        break;
      case LogLevel.Finest:
        bunyanLevel = bunyan.TRACE;
        break;
      default:
        throw new Error(`Unknown LogLevel ${lev}`);
    }
    this.bunyanLogger.level(bunyanLevel);
    this.logLevelBacking = lev;
  }

  private logLevelBacking: LogLevel = LogLevel.Debug;
  
  constructor(name: string, logLevel: LogLevel = LogLevel.Debug) {
    this.bunyanLogger = bunyan.createLogger({
      name: name,
      streams: [
        {
          stream: process.stderr,
          level: bunyan.TRACE
        }
      ]
    });

    this.logLevel = logLevel;
  }
  
  public error(message: string) {
    if (this.logLevel >= LogLevel.Error) {
      this.bunyanLogger.error(message);
    }
  }

  public warning(message: string) {
    if (this.logLevel >= LogLevel.Warning) {
      this.bunyanLogger.warn(message);
    }
  }
  
  public info(message: string) {
    if (this.logLevel >= LogLevel.Info) {
      this.bunyanLogger.info(message);
    }
  }
  
  public debug(message: string) {
    if (this.logLevel >= LogLevel.Debug) {
      this.bunyanLogger.debug(message);
    }
  }
  
  public finest(messageGenerator: () => string) {
    if (this.logLevel >= LogLevel.Finest) {
      this.bunyanLogger.trace(messageGenerator());
    }
  }
}
