@rem Usage: CreateSelfSignedCert.cmd
@rem
@rem Derived from examples at
@rem https://stackoverflow.com/questions/10175812/how-to-create-a-self-signed-certificate-with-openssl#10176685
@rem
@rem Assumes OpenSSL-Win64 is installed from https://slproweb.com/products/Win32OpenSSL.html
@rem The "light" version is sufficient. Install binaries into the bin\ directory, not System32.

set OPENSSL_PATH=c:\OpenSSL-Win64\bin

%OPENSSL_PATH%\openssl.exe req -x509 -nodes -days 730 -newkey rsa:2048 -keyout SQRLTestSite.PrivateKey.pem -out SQRLTestSite.FullChain.pem -config %~dp0SelfSigned.cnf
