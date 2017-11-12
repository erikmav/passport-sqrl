// Primary entry point for the test web site. Starts the Express-based
// site within Node, with the passport-sqrl plugin configured.

import { LogLevel } from '../passport-sqrl';
import * as logging from './Logging';
import { TestSiteHandler } from './TestSiteHandler';

const log = new logging.BunyanLogger("testSite", LogLevel.Finest);
let testSiteHandler = new TestSiteHandler(log);
