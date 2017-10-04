// Logging interface, with implementations typically defined in
// specific component implementations to match local requirements.

import * as bunyan from 'bunyan';

// When the log level is less than or equal to the level of a specific log trace
// it is emitted to the log destination.
export enum LogLevel { Error, Warning, Info, Debug, Finest }

export interface ILogger {
  // Gets or sets the current log level.
  logLevel: LogLevel;
  
  error(message: string): void;
  warning(message: string): void;
  info(message: string): void;
  debug(message: string): void;
  finest(message: string): void;
}

export class BunyanLogger implements ILogger {
  public bunyanLogger: bunyan;
  public logLevel: LogLevel;

  constructor(name: string) {
    this.bunyanLogger = bunyan.createLogger({
      name: name,
      streams: [
        {
          stream: process.stderr,
          level: "debug"
        }
      ]
    });

    this.logLevel = LogLevel.Debug;
  }
  
  public error(message: string) {
    if (this.logLevel <= LogLevel.Error) {
      this.bunyanLogger.error(message);
    }
  }

  public warning(message: string) {
    if (this.logLevel <= LogLevel.Warning) {
      this.bunyanLogger.warn(message);
    }
  }
  
  public info(message: string) {
    if (this.logLevel <= LogLevel.Info) {
      this.bunyanLogger.info(message);
    }
  }
  
  public debug(message: string) {
    if (this.logLevel <= LogLevel.Debug) {
      this.bunyanLogger.debug(message);
    }
  }
  
  public finest(message: string) {
    if (this.logLevel <= LogLevel.Finest) {
      this.bunyanLogger.trace(message);
    }
  }
}
