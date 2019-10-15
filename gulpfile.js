//
// Root Gulp file for building the project code.
// Gulp home is at http://gulpjs.com/ 
//

"use strict";

// Base Gulp library.
var gulp = require('gulp');

// Node.js's exec() for use in running command line tools.
var execCommand = require('child_process').exec;

// pump makes it easier to debug chains of Node.js streams.
// https://github.com/mafintosh/pump
var pump = require('pump');

// del allows cleaning up folders and files. 
const del = require('del');

// Helper method - allows recursive copying a directory structure.
// http://stackoverflow.com/questions/25038014/how-do-i-copy-directories-recursively-with-gulp#25038015
// 'finishedAsyncTaskCallback' param is optional and is the Gulp completion callback for asynchronous tasks.
// If specified it will be called after this method completes.
gulp.copy = (src, dest, finishedAsyncTaskCallback) => {
  return pump([
    gulp.src(src, { base:"." }),
    gulp.dest(dest)
  ], finishedAsyncTaskCallback);
};

// Gulp wrapper for running Mocha tests.
const mocha = require('gulp-mocha');

const gulpTypescript = require('gulp-typescript');
const tslint = require("gulp-tslint");
const sourcemaps = require('gulp-sourcemaps');
const linecorr = require('gulp-line-ending-corrector');
const jsonModify = require('gulp-json-modify');

// Keep important paths here for reference. Only use Paths.Xxx in code below instead of duplicating these strings.
var Paths = {
  SourceRoot: 'src',

  // Common code used across main code, unit tests, integration tests.
  PassportSqrlRoot: 'src/passport-sqrl',

  // Passport-SQRL unit tests.
  PassportSqrlTests: 'src/SqrlTests',

  // Passport-SQRL integration tests.
  PassportSqrlIntegrationTests: 'src/IntegrationTests',
  
  // Integration test web site hosted via Node.js.
  TestSiteRoot: 'src/testSite',
  Certs: 'src/Certs',

  // Build output locations
  OutputRoot: 'out',
    
  PackageOutput: 'out/passport-sqrl',

  PassportSqrlTestsOutput: 'out/SqrlTests',

  TestSiteOutput: 'out/testSite',
  TestSiteTestsOutput: 'out/testSiteClient',
  IntegrationTestsOutput: 'out/IntegrationTests',
};

gulp.task('clean', () => {
  // Clean up output directories.
  return del([ Paths.OutputRoot ]);
});

gulp.task('tslint', () => {
  return gulp.src(Paths.SourceRoot + "/**/*.ts")
      .pipe(tslint({
        formatter: "verbose"
      }))
      .pipe(tslint.report())
});

gulp.task('transpile-main-package', () => {
  return gulp.src(Paths.PassportSqrlRoot + '/index.ts')
      .pipe(gulpTypescript.createProject('tsconfig.json', {
        declaration: true
      })())
      .pipe(gulp.dest(Paths.PackageOutput));
});
gulp.task('copy-package-json', () => {
  // The repo's package.json acts as the source for the package, but we strip out a bit of info.
  return gulp.src('./package.json')
      // By convention, dependencies are those for passport-sqrl/index.ts, devDependencies for testing.
      .pipe(jsonModify({ key: 'devDependencies', value: {} }))
      .pipe(gulp.dest(Paths.PackageOutput));
});
gulp.task('copy-package-readme', () => {
  // The repo's README.md is used for the package.
  return gulp.src('./README.md')
      .pipe(gulp.dest(Paths.PackageOutput));
});

gulp.task('transpile-sqrl-tests', () => {
  return gulp.src(Paths.PassportSqrlTests + '/**/*.ts')
      .pipe(sourcemaps.init())
      .pipe(gulpTypescript.createProject('tsconfig.json')())
      .pipe(sourcemaps.write('.'))
      .pipe(gulp.dest(Paths.PassportSqrlTestsOutput));
});
gulp.task('copy-sqrl-tests-static-files', () => {
  return gulp.src([
      Paths.Certs + '/TestSite.FullChain.Cert.pem'  // Test site cert chain
    ])
    .pipe(gulp.dest(Paths.PassportSqrlTestsOutput));
});

gulp.task('transpile-sqrl-integration-tests', () => {
  return gulp.src(Paths.PassportSqrlIntegrationTests + '/**/*.ts')
      .pipe(sourcemaps.init())
      .pipe(gulpTypescript.createProject('tsconfig.json')())
      .pipe(sourcemaps.write('.'))
      .pipe(gulp.dest(Paths.IntegrationTestsOutput));
});
gulp.task('copy-sqrl-integration-tests-static-files', () => {
  return gulp.src([
      Paths.Certs + '/TestSite.FullChain.Cert.pem'  // Test site cert chain
    ])
    .pipe(gulp.dest(Paths.IntegrationTestsOutput));
});

// http://andrewconnell.com/blog/running-mocha-tests-with-visual-studio-code
gulp.task('run-passport-sqrl-unit-tests', () => {
  return gulp.src(Paths.PassportSqrlTestsOutput + '/**/*.js', { read: false })
    .pipe(mocha({ reporter: 'spec' }));
});

// http://andrewconnell.com/blog/running-mocha-tests-with-visual-studio-code
gulp.task('run-test-site-integration-tests', () => {
  return gulp.src(Paths.IntegrationTestsOutput + '/Sqrl.IntegrationTests.js', { read: false })
    .pipe(mocha({ reporter: 'spec' }));
});

gulp.task('transpile-test-site', () => {
  return gulp.src(Paths.TestSiteRoot + '/**/*.ts')
      .pipe(sourcemaps.init())
      .pipe(gulpTypescript.createProject('tsconfig.json')())
      .pipe(sourcemaps.write('.'))
      .pipe(gulp.dest(Paths.TestSiteOutput));
});
gulp.task('copy-test-site-static-files', () => {
  return gulp.src([
      Paths.TestSiteRoot + '/**/*.ico',
      Paths.TestSiteRoot + '/**/*.png',
      Paths.TestSiteRoot + '/**/*.html',
      Paths.TestSiteRoot + '/**/*.css',
      Paths.TestSiteRoot + '/**/*.ejs',
      Paths.TestSiteRoot + '/**/*.js',
      Paths.Certs + '/*.Cert.pem',  // Test site cert chain
      Paths.Certs + '/TestSite.PrivateKey.pem',  // Test site leaf cert key
      Paths.Certs + '/RootCert.Cert.cer'  // Test site cert chain
    ])
    .pipe(gulp.dest(Paths.TestSiteOutput));
});

// ---------------------------------------------------------------------------
// Primary entry point commands: Running 'gulp' cleans and runs build,
// 'build' is an alias for 'default' and required by Visual Studio Code
// integration.
// ---------------------------------------------------------------------------
gulp.task('default', gulp.series(
  'clean',

  gulp.parallel(
    'tslint',
    'transpile-main-package',
    'transpile-sqrl-tests',
    'transpile-sqrl-integration-tests',
    'transpile-test-site',

    'copy-test-site-static-files',
    'copy-sqrl-tests-static-files',
    'copy-sqrl-integration-tests-static-files',

    'copy-package-json',
    'copy-package-readme',
  ),

  gulp.parallel(
    'run-passport-sqrl-unit-tests',
    'run-test-site-integration-tests',
  ),
));
gulp.task('build', gulp.series('default'));
