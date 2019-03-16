@echo off
@rem NPM publish script

where npm
if ERRORLEVEL 1 echo ERROR: NPM not found. Did you install Node.js? && exit /b 1

echo.
echo Log in to NPM:
call npm login
if ERRORLEVEL 1 echo ERROR: Login failed && exit /b 1

echo.
echo Publishing package
call npm publish out/passport-sqrl %*
if ERRORLEVEL 1 echo ERROR: Publish failed && exit /b 1

exit /b 0
