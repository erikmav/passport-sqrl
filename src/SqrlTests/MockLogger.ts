import { ILogger, LogLevel } from '../passport-sqrl';

/** Common test mock */
export class MockLogger implements ILogger {
  public logLevel: LogLevel = LogLevel.Debug;

  public error(message: string): void {
    console.log(`ERROR: ${message}`);
  }
  public warning(message: string): void {
    console.log(`Warn: ${message}`);
  }
  public info(message: string): void {
    console.log(message);
  }
  public debug(message: string): void {
    console.log(message);
  }
  public finest(messageGenerator: () => string): void {
    console.log(messageGenerator());
  }
}
