@echo off
rem Setup script for Windows consoles.
rem Can be run over and over if you need to. If you see package.json change when
rem you do a git pull, you should run it again to pull down any Node.js
rem NPM packages or perform other setups.

where npm
if ERRORLEVEL 1 echo ERROR: NPM not found. Did you install Node.js? && exit /b 1

echo.
echo ==========================================================================
echo Ensuring we have all the needed Node.js Package Manager packages.
echo ==========================================================================

echo.
echo ==========================================================================
echo Installing Gulp ^(http://gulpjs.com/^) command line
echo We use this as a cross-operating-system way to build code instead of
echo trying to use Windows command scripts.
echo ==========================================================================
echo.
call npm install --global gulp-cli
if ERRORLEVEL 1 echo ERROR: npm install --global gulp-cli failed with errorlevel %ERRORLEVEL% && exit /b 1

echo.
echo ==========================================================================
echo Installing NodeJS (NPM) packages in root directory, dev mode.
echo These packages form the basic underpinnings of the whole repo.
echo Including:
echo.
echo Build tools and Gulp modules:
echo   gulp - adds as a dev dependency
echo   pump - simplifies dealing with Node.js streams when lots of piping is used.
echo   del - deletes files and folders
echo   gulp-typescript - TypeScript builds for Gulp
echo   tslint - TSLint installation for compile-time linting.
echo     https://palantir.github.io/tslint/
echo   gulp-tslint - TSLint integration for Gulp
echo   gulp-sourcemaps - sourcemap generator for improved debugging of TypeScript
echo   gulp-line-ending-corrector - Updates Windows to Unix line endings during build
echo.
echo Development modules:
echo   typescript - TypeScript plug-in, since basic JavaScript is far too permissive
echo   @types/node - TypeScript .d.ts description for Node.js - see
echo     https://basarat.gitbooks.io/typescript/content/docs/quick/nodejs.html
echo   Mocha - unit testing framework that uses Node.js and fits well into
echo     Visual Studio Code. https://mochajs.org/
echo   gulp-mocha - Lets us run Mocha within Gulp to run tests each time we build.
echo   Chai - assertion library for use in Mocha. http://chaijs.com/
echo   rimraf - recursive directory operations used in test code.
echo   request - HTTP client package used in unit and integration tests.
echo   request-debug - deeper debugging for request.
echo   request-promise-native - Promises/async support for request.
echo.
echo Integration test modules:
echo   bunyan - node.js line-oriented JSON logger
echo   Express - web site framework. http://expressjs.com/
echo   passport - PassportJS authentication framework, used in Express.
echo     https://github.com/jaredhanson/passport
echo.
echo @types/* - TypeScript type definitions for each module.
echo ==========================================================================
call npm install
if ERRORLEVEL 1 echo ERROR: npm install failed for root modules with errorlevel %ERRORLEVEL% && exit /b 1


call %~dp0Init.cmd

echo.
echo ==========================================================================
echo Complete!
echo ==========================================================================
echo.
