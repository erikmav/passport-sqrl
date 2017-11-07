# Passport-SQRL
A [PassportJS](https://github.com/jaredhanson/passport) implementation of the [SQRL authentication protocol](https://www.grc.com/sqrl/sqrl.htm).

```diff
- NOTE: This repo is under construction.
- The real NPM package has not been published yet.
```

The code for this repo is written in TypeScript, with the JavaScript outputs transcoded to ES6 for modern Node.js compatibility. The resulting output is published as an NPM module 'passport-sqrl'.

# Using This Repo - Windows

1. Install Git from https://git-scm.com/download/win (for Windows), or https://git-scm.com/download for other operating systems. Be sure you're using at least version 2.14.1 to get an important security patch.
1. Install Node.js from https://nodejs.org (click the Current button to get the latest - you need at least version 8.4).
1. (Windows) Install Python version 2.7 from https://www.python.org/ . You can install just for your local user account or for all users. Version 2.7 is required for building the Ed25519 native code package.
1. (Windows) Install Visual Studio 2017 Build Tools from https://www.visualstudio.com/thank-you-downloading-visual-studio/?sku=BuildTools&rel=15 - also needed for building native code. Select the Visual C++ Build Tools suite from the Workloads tab.
1. (Windows) Install the latest Win64 version of the full (non-Lite) installer for OpenSSL from https://slproweb.com/products/Win32OpenSSL.html to its default install location (c:\OpenSSL-Win64). This is needed to link the Ed25519 native code package. Select the option to install binaries to the OpenSSL bin directory. Donate $10.

* We recommend Visual Studio Code from https://www.visualstudio.com/products/code-vs - run `code .` in the repo root folder. You should install the "TSLint" extension which runs the lint tool as you type.
* The `Setup.cmd` command should be run after any pull from GitHub to install latest packages.
* The `Init.cmd` command (which is run by Setup.cmd or can be run separately) sets up some useful command shortcuts, such as `pull` for `git pull`, `nb <shortname>` and `cb <shortname>` to create or change to a local topic branch to work in (of the form dev/your-github-alias/shortname). See aliases.txt for all the commands.
* Submit pull requests on GitHub at https://github.com/erikma/passport-sqrl

## Building code
We use Gulp (https://gulpjs.org/) as a build system. We have integrated Gulp into Visual Studio Code to make life easier. To run a build, press `Ctrl+Shift+B` and ensure you have no errors showing in VSCode.

Building the code places the results into the out/ folder.

You can also run the build in the Windows console if you need to by running the command `gulp`.

## Unit tests
A "pure" unit test suite for the passport-sqrl code is under the src/SqrlTests directory and built into the build, and its failure causes the build to fail.

## Integration tests
There is a suite of tests that start up a Node server with Express, Passport, and passport-sqrl for integration testing. These are not "pure" unit tests but they also cause the build to fail if they are not working.

You'll need to be on a network for these to work. (Running in airplane mode will cause failures. But many flights have wifi. :)

## Browser testing
The same NodeJS + Express + Passport + passport-sqrl web site can be run from VSCode. It uses HTTPS on port 5858.

To run the site:

1. Press the F5 key while in VSCode.
1. If a warning bar about build errors appears, click Debug Anyway
1. If a firewall popup appears, allow Node.js to open port 5858
1. Wait for the orange debugging color to appear in the status bar.

Then:

1. Open a browser and navigate to https://your-machine-name:5858
1. Allow a security exception for the self-signed certificate.
1. You should be redirected to the /login page and see a SQRL QR-Code that can also be clicked.
1. When clicked, the desktop SQRL client should activate to handle the sqrl:// URL and allow you to log in.

'''NOTE: Desktop flow is broken because of the self-signed certificate'''

## Useful Links

* SQRL main page: https://www.grc.com/sqrl/sqrl.htm
* SQRL link protocol to a site login page: https://www.grc.com/sqrl/protocol.htm and https://www.grc.com/sqrl/semantics.htm
* SQRL web server expected behavior: https://www.grc.com/sqrl/server.htm
