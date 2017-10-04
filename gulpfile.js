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
gulp.copy = function(src, dest, finishedAsyncTaskCallback) {
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

// Keep important paths here for reference. Only use Paths.Xxx in code below instead of duplicating these strings.
var Paths = {
    SourceRoot: 'src',

    // Common code used across main code, unit tests, integration tests.
    PassportSqrlRoot: 'src/passport-sqrl',
    PassportSqrlAll: 'src/passport-sqrl/**',

    // Passport-SQRL unit tests.
    PassportSqrlTests: 'src/SqrlTests',
    PassportSqrlTestsAll: 'src/SqrlTests/**',
    
    // Integration test web site hosted via Node.js.
    TestSiteRoot: 'src/testSite',
    TestSiteAll: 'src/testSite/**',
    TestSiteTests: 'src/testSiteClient',

    // Build output locations
    OutputRoot: 'out',
    
    PassportSqrlTestsOutput: 'out/SqrlTests',

    TestSiteOutput: 'out/testSite',
    TestSiteTestsOutput: 'out/testSiteClient',

    InitialSetupOutput: 'out/InitialSetup',
    InitialSetupOutputShared: 'out/InitialSetup/shared',
    InitialSetupOutputTools: 'out/InitialSetup/tools',
};

// ---------------------------------------------------------------------------
// Primary entry point commands: Running 'gulp' cleans and runs build,
// 'build' is an alias for 'default' and required by Visual Studio Code
// integration.
// ---------------------------------------------------------------------------
gulp.task('default', [
    'clean',
    
    'tslint',
    'transpile-typescript',

    //'copy-test-site-static-files'
    //'run-passport-sqrl-unit-tests',
    //'run-test-site-integration-tests',
]);
gulp.task('build', ['default']);

gulp.task('clean', () => {
    // Clean up output directories.
    // .sync() version forces completion before returning from task, making
    // it complete before the next task in a dependency list.
    return del.sync([ Paths.OutputRoot ]);
});

gulp.task("tslint", [], () => {
    return gulp.src(Paths.SourceRoot + "/**/*.ts")
        .pipe(tslint({
            formatter: "verbose"
        }))
        .pipe(tslint.report())
});

gulp.task('transpile-typescript', [], () => {
    return gulp.src(Paths.SourceRoot + '/**/*.ts')
        .pipe(sourcemaps.init())
        .pipe(gulpTypescript.createProject('tsconfig.json')())
        .pipe(sourcemaps.write('.'))
        .pipe(gulp.dest(Paths.SharedOutput));
});

// http://andrewconnell.com/blog/running-mocha-tests-with-visual-studio-code
gulp.task('run-test-site-integration-tests', ['transpile-typescript', 'copy-test-site-static-files'], () => {
  return gulp.src(Paths.TestSiteTestsOutput + '/SQRL.tests.js', { read: false })
    .pipe(mocha({ reporter: 'spec' }));
});

// http://andrewconnell.com/blog/running-mocha-tests-with-visual-studio-code
gulp.task('run-passport-sqrl-unit-tests', ['transpile-typescript'], () => {
  return gulp.src(Paths.PassportSqrlTests + '/**/*.tests.js', { read: false })
    .pipe(mocha({ reporter: 'spec' }));
});

gulp.task('copy-test-site-static-files', [], () => {
    return gulp.src([
            Paths.TestSiteRoot + '/**/*.ico',
            Paths.TestSiteRoot + '/**/*.html',
            Paths.TestSiteRoot + '/**/*.css',
        ])
        .pipe(gulp.dest(Paths.TestSiteOutput));
});
