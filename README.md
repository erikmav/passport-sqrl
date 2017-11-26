# Passport-SQRL
An [ExpressJS](http://expressjs.com/) and [PassportJS](https://github.com/jaredhanson/passport) implementation of the [SQRL authentication protocol](https://www.grc.com/sqrl/sqrl.htm).

The code is written in TypeScript, with the transcoded JavaScript outputs targeted to ES6 for modern Node.js compatibility. The resulting output is published as NPM module 'passport-sqrl'.

# Using the Package
SQRL does not present its credentials in the HTTP Authenticate header, and so requires several integration points in a site:

1. ExpressJS middleware is needed to handle SQRL API calls like 'query', 'ident', 'disable', 'enable', 'remove'.
1. A PassportJS Strategy pairs with the API handler.
1. The site must implement an ISQRLIdentityStorage implementation to store user profile information and SQRL "nut" mappings for use by the passport-sqrl components.
1. For best effect, the site's login page should poll for login completion to handle the SQRL app case, e.g. phone login or the separate SQRL desktop app. Because the app data flow does not integrate with the user's browser (by design - the phone login case is important for insecure Internet cafe scenarios), the browser will not be able to tell when the login has been completed - and get an ambient auth cookie - without polling the site.

The demo site code in the passport-sqrl Git repo (https://github.com/erikma/passport-sqrl/tree/master/src/testSite especially TestSiteHandler.ts and login.ejs) demonstrates the integration steps above. See the section below on using the test site for browser testing.

# Release History and Release Notes

## 0.2.0 25 Nov 2017
* Breaking change in ISQRLIdentityStorage - function names updated for consistent Async suffix, e.g. query -> queryAsync
* Removed AuthCallback from module exports (obsolete).
* Fixed bug in SQRL URL generator - base64 encoding was mistakenly used for the nut in 0.1.0, causing problems with '+' values in the base64 string  being interpreted as spaces. Updated to issue URLs with base64url values.
* Test site security updates: CSP header and IFRAME embed protection. Refactored inline scripts to /Scripts directory to match CSP needs.

## 0.1.0 15 Nov 2017
* Initial release with 'query' and 'ident' API calls supported
* Successful login using mid-November desktop SQRL client. No successful logins with Android phone app yet. iOS app not tried.
* Integration test web site (esp. TestSiteHandler.ts) in package's repo demonstrates how to use the package.
* SQRL v1 spec still in flux, expect breakage.

# Using the Test Site
You'll need to clone the package's home repo from https://github.com/erikma/passport-sqrl to get all the sample code.

## Dev Environment Setup

1. Install the latest SQRL desktop client from [GRC's site](https://www.grc.com/dev/sqrl.exe)
1. Install Git from https://git-scm.com/download/win (for Windows), or https://git-scm.com/download for other operating systems. Be sure you're using at least version 2.14.1 to get an important security patch.
1. Install Node.js from https://nodejs.org (click the Current button to get the latest - you need at least version 8.9.1).
1. (Windows) Install Python version 2.7 from https://www.python.org/ . You can install just for your local user account or for all users. Version 2.7 is required for building the Ed25519 native code package.
1. (Windows) Install Visual Studio 2017 Build Tools from https://www.visualstudio.com/thank-you-downloading-visual-studio/?sku=BuildTools&rel=15 - also needed for building native code. Select the Visual C++ Build Tools suite from the Workloads tab.
1. (Windows) Install the latest Win64 version of the full (non-Lite) installer for OpenSSL from https://slproweb.com/products/Win32OpenSSL.html to its default install location (c:\OpenSSL-Win64). This is needed to link the Ed25519 native code package. Select the option to install binaries to the OpenSSL bin directory. Donate $10.

* We recommend Visual Studio Code from https://www.visualstudio.com/products/code-vs - run `code .` in the repo root folder. You should install the "TSLint" extension which runs the lint tool as you type.
* (Windows) The `Setup.cmd` command should be run after any pull from GitHub to install latest packages.
* (Windows) The `Init.cmd` command (which is run by Setup.cmd or can be run separately) sets up some useful command shortcuts.

## Building code
We use [Gulp](https://gulpjs.org/) as a build system. We have integrated Gulp into Visual Studio Code to make life easier. To run a build, press `Ctrl+Shift+B` and ensure you have no errors showing in VSCode.

Building the code places package contents and test code into the out/ folder.

You can also run the build in the console if you need to by running the command `gulp`.

## Unit tests
A "pure" unit test suite for the passport-sqrl code is under the src/SqrlTests directory and built into the build. Its failure causes the build to fail.

## Integration tests
There is a suite of tests that start up a Node server with Express, Passport, and passport-sqrl for integration testing. These are not "pure" unit tests but they also cause the build to fail if they are not working.

You'll need to be on a network for these to work. (Running in airplane mode will cause failures. But many flights have wifi. :)

The integration tests also make use of a mock SQRL client that knows how to run the client side of the protocol. This could be useful in its own right if you want to extract it for general purpose use in a JavaScript based client environment.

## Browser Testing with the Test Site
The same NodeJS + Express + Passport + passport-sqrl web site can be run from VSCode. It uses HTTPS on port 5858 and HTTP on port 5857.

### Installing the Test Site Trusted Root Certificate
The test site uses a certificate chain generated in a custom Certificate Authority under the src\Certs directory. It includes a root, intermediate, and leaf cert. The site uses the leaf as its HTTPS identity. To allow your device's browser to trust the site's cert chain, you need to add the root certificate as a trusted certificate authority.

A small HTTP-only site is started when you build and run the test site. Navigate to http://your-machine-IP:5859/certs from your computer or device. (If the connection times out, check your Windows computer's firewall settings and ensure node.exe is allowed to listen on ports 5858 and 5859 for private networks.) Follow the instructions on the page to install RootCert.Cert.pem (Android) or RootCert.Cert.cer (Windows) as a trusted root.

Note that http://your-machine-IP:5859 will redirect from the HTTP to the HTTPS site; only the /certs page noted above is open for browsing under HTTP.

### To Run the Site

1. Press the F5 key while in VSCode.
1. If a firewall popup appears, allow Node.js to open port 5858 and 5859
1. Wait for the orange debugging color to appear in the status bar.

### Testing with a Browser

1. Open a browser and navigate to https://your-machine-IP:5858
1. Allow a security exception for the certificate (if needed).
1. You should be redirected to the /login page and see a SQRL QR-Code that can be clicked to launch the desktop app, or snapshotted from a phone app.
1. When clicked, the desktop SQRL client should activate to handle the sqrl:// URL and allow you to log in.
1. After login is completed, the /login page on the site should soon realize the login is done and automatically redirect to the site root, showing your SQRL public key that is acting as your identity.

# Useful Links

* SQRL main page: https://www.grc.com/sqrl/sqrl.htm
* SQRL link protocol to a site login page: https://www.grc.com/sqrl/protocol.htm and https://www.grc.com/sqrl/semantics.htm
* SQRL web server expected behavior: https://www.grc.com/sqrl/server.htm
