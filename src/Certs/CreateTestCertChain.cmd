@rem Regenerates the full cert chain for use with localhost testing

@rem https://stackoverflow.com/questions/94445/using-openssl-what-does-unable-to-write-random-state-mean
@rem https://stackoverflow.com/questions/4051883/batch-script-how-to-check-for-admin-rights#11995662
@NET SESSION >nul 2>&1
@IF %ERRORLEVEL% NEQ 0 echo ERROR: You must run in cmd.exe running as administrator && exit /B 0

call CreateRoot.cmd "SQRL Test Root"
if ERRORLEVEL 1 echo Creating root failed with errorlevel %ERRORLEVEL% && exit /b 1

call CreateIntermediate.cmd "SQRL Test Site Intermediate" TestSiteIntermediate
if ERRORLEVEL 1 echo Creating intermediate failed with errorlevel %ERRORLEVEL% && exit /b 1

call CreateLeaf.cmd "localhost" TestSiteIntermediate TestSite
if ERRORLEVEL 1 echo Creating intermediate failed with errorlevel %ERRORLEVEL% && exit /b 1

copy /y TestSiteIntermediate.Cert.pem+RootCert.Cert.pem TestSite.FullChain.Cert.pem

@rem .pem is not known to Windows, copy to .cer as well to allow installation via Windows Explorer.
copy /y RootCert.Cert.pem RootCert.Cert.cer
copy /y TestSiteIntermediate.Cert.pem TestSiteIntermediate.Cert.cer

exit /b 0
