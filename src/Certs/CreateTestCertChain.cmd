@rem Regenerates the full cert chain for use with localhost testing

call CreateRoot.cmd "SQRL Test Root"
if ERRORLEVEL 1 echo Creating root failed with errorlevel %ERRORLEVEL% && exit /b 1

call CreateIntermediate.cmd "SQRL Test Site Intermediate" TestSiteIntermediate
if ERRORLEVEL 1 echo Creating intermediate failed with errorlevel %ERRORLEVEL% && exit /b 1

call CreateLeaf.cmd "localhost" TestSiteIntermediate TestSite
if ERRORLEVEL 1 echo Creating intermediate failed with errorlevel %ERRORLEVEL% && exit /b 1

copy /y TestSiteIntermediate.Cert.pem+RootCert.Cert.pem TestSite.FullChain.Cert.pem

exit /b 0
