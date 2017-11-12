@rem Creates a leaf cert key pair signed with a designated intermediate cert.
@rem
@rem IMPORTANT: For non-test purposes the key must be protected - do NOT
@rem check into source control, instead place on a USB stick that is kept offline
@rem except for rare cases where it is used to install the certificate.
@rem
@rem Usage: CreateLeaf "Subject String" "IntermediateBaseFilename" "BaseFilename"
@rem E.g.: CreateLeaf "localhost" TestSiteIntermediate TestSite
@rem Expects IntermediateBaseFilename.PrivateKey.pem and IntermediateBaseFilename.Cert.pem generated
@rem by CreateIntermediate.cmd to be in the current directory.
@rem
@rem Derived from https://stackoverflow.com/questions/19665863/how-do-i-use-a-self-signed-certificate-for-a-https-node-js-server#24749608 and
@rem https://jamielinux.com/docs/openssl-certificate-authority/create-the-root-pair.html
@rem
@rem Assumes OpenSSL-Win64 is installed from https://slproweb.com/products/Win32OpenSSL.html
@rem The "light" version is sufficient. Install binaries into the bin\ directory, not System32.

@rem https://stackoverflow.com/questions/94445/using-openssl-what-does-unable-to-write-random-state-mean
@rem https://stackoverflow.com/questions/4051883/batch-script-how-to-check-for-admin-rights#11995662
@NET SESSION >nul 2>&1
@IF %ERRORLEVEL% NEQ 0 echo ERROR: You must run in cmd.exe running as administrator && exit /B 0

setlocal ENABLEDELAYEDEXPANSION

set OPENSSL_PATH=c:\OpenSSL-Win64\bin\openssl.exe
set SUBJECT=/C=US/ST=WA/L=Bothell/O=passport-sqrl/CN=%~1
set INT_FILENAME_BASE=%~2
if "%INT_FILENAME_BASE%"=="" set INT_FILENAME_BASE=Intermediate
set FILENAME_BASE=%~3
if "FILENAME_BASE%"=="" set FILENAME_BASE=Leaf

set ROOT_CERT=RootCert.Cert.pem
set INT_PRIV=%INT_FILENAME_BASE%.PrivateKey.pem
set INT_CERT=%INT_FILENAME_BASE%.Cert.pem
set LEAF_PRIV=%FILENAME_BASE%.PrivateKey.pem
set LEAF_CERT=%FILENAME_BASE%.Cert.pem

@rem Short key length for leaf key for reduced wire transmission size and CPU load for validation.
%OPENSSL_PATH% genrsa -out %LEAF_PRIV% 2048
if ERRORLEVEL 1 echo genrsa failed with errorlevel %ERRORLEVEL% && exit /b 1

%OPENSSL_PATH% req -new -key %LEAF_PRIV% -out %FILENAME_BASE%.csr.pem -subj "%SUBJECT%" -config CertRequestTemplate.cnf
if ERRORLEVEL 1 echo Creation of Cert Signing Request failed with errorlevel %ERRORLEVEL% && exit /b 1

@rem Use the intermediate cert and CA database to sign the leaf
@rem http://certificate.fyicenter.com/2115_OpenSSL_ca_Command_Options.html
@echo.
%OPENSSL_PATH% ca -verbose -config CertRequestTemplate.cnf -name intermediate_ca -extensions v3_leaf_policy -in %FILENAME_BASE%.csr.pem -cert %INT_CERT% -keyfile %INT_PRIV% -out %LEAF_CERT% -outdir . -days 3650 -batch
if ERRORLEVEL 1 echo Signing of leaf public cert with intermediate certificate authority cert and key failed with errorlevel %ERRORLEVEL% && exit /b 1

del %FILENAME_BASE%.csr.pem

@rem Verify our result by ensuring the leaf chains to intermediate and root.
%OPENSSL_PATH% verify -verbose -CAfile %ROOT_CERT% -untrusted %INT_CERT% %LEAF_CERT%
if ERRORLEVEL 1 echo Validation of leaf cert failed with errorlevel %ERRORLEVEL% && exit /b 1

echo Wrote private key into %LEAF_PRIV% and cert into %LEAF_CERT%

exit /b 0
