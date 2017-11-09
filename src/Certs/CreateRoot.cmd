@rem Creates a large root key pair and self-signed cert.
@rem
@rem IMPORTANT: For non-test purposes the key must be protected offline - do NOT
@rem check into source control, instead place on a USB stick that is kept offline
@rem except for rare cases where it is used to create intermediate certs.
@rem
@rem Usage: CreateRoot "Subject String"
@rem E.g.: CreateRoot "SQRL Test Root"
@rem
@rem Derived from https://stackoverflow.com/questions/19665863/how-do-i-use-a-self-signed-certificate-for-a-https-node-js-server#24749608 and
@rem https://jamielinux.com/docs/openssl-certificate-authority/create-the-root-pair.html
@rem
@rem Assumes OpenSSL-Win64 is installed from https://slproweb.com/products/Win32OpenSSL.html
@rem The "light" version is sufficient. Install binaries into the bin\ directory, not System32.

setlocal ENABLEDELAYEDEXPANSION

set OPENSSL_PATH=c:\OpenSSL-Win64\bin\openssl.exe
set SUBJECT=/C=US/ST=WA/L=Bothell/O=passport-sqrl/CN=%~1
set ROOT_PRIV=RootCert.PrivateKey.pem
set ROOT_CERT=RootCert.Cert.pem

@rem Long key length for root key to last longer against brute force or quantum attack.
%OPENSSL_PATH% genrsa -out %ROOT_PRIV% 4096
if ERRORLEVEL 1 echo genrsa failed with errorlevel %ERRORLEVEL% && exit /b 1

%OPENSSL_PATH% req -x509 -new -nodes -key %ROOT_PRIV% -days 10000 -out %ROOT_CERT% -subj "%SUBJECT%" -config CertRequestTemplate.cnf -extensions v3_root_ca_policy
if ERRORLEVEL 1 echo Creation of root public cert failed with errorlevel %ERRORLEVEL% && exit /b 1

echo Wrote private key into %ROOT_PRIV% and cert into %ROOT_CERT%

exit /b 0
