# Passport-SQRL
A PassportJS (https://github.com/jaredhanson/passport) implementation of the SQRL authentication protocol (https://www.grc.com/sqrl/sqrl.htm).

The code for this repo is written in TypeScript, with the JavaScript outputs transcoded to ES6 for modern Node.js compatibility. The resulting output is published as an NPM module 'passport-sqrl'.

# Using This Repo - Windows

1. Install Git from https://git-scm.com/download/win (for Windows), or https://git-scm.com/download for other operating systems. Be sure you're using at least version 2.14.1 to get an important security patch.
1. Install Node.js from https://nodejs.org (click the Current button to get the latest - you need at least version 8.4).

* We recommend visual Studio Code from https://www.visualstudio.com/products/code-vs - run `code .` in the repo root folder.
* The `Setup.cmd` command should be run after any pull from GitHub to install latest packages.
* The `Init.cmd` command (which is run by Setup.cmd or can be run separately) sets up some useful command shortcuts, such as `pull` for `git pull`, `nb <shortname>` and `cb <shortname>` to create or change to a local topic branch to work in (of the form dev/<your-github-alias>/shortname). See aliases.txt for all the commands.
* Submit pull requests on GitHub at https://github.com/erikma/passport-sqrl

## Building code
We use Gulp (https://gulpjs.org/) as a simple build system to convert code files into final results.
We have integrated Gulp into Visual Studio Code to make life easier. To run a build, press `Ctrl+Shift+B` and ensure you have no errors showing in VSCode.

Building the code places the results into the out/ folder.

You can also run the build in the Windows console if you need to by running the command `gulp`.

## Useful Links

* SQRL main page: https://www.grc.com/sqrl/sqrl.htm
* SQRL link protocol to a site login page: https://www.grc.com/sqrl/protocol.htm and https://www.grc.com/sqrl/semantics.htm
* SQRL web server expected behavior: https://www.grc.com/sqrl/server.htm
