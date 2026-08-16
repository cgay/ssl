*****************************
ssl - A Dylan OpenSSL Wrapper
*****************************

This package provides a Dylan wrapper for OpenSSL and interfaces to make secure sockets
work with the Open Dylan "network" library.

This code is experimental. It still misses some features:

* Certificate verification (revocation lists, etc.)
* Certificates shielded with a user password, provide callback method for password.
* Currently only supports TCP sockets.

Proper usage for ssl sockets are shown in '../examples/ssl-echo-{server,client}'
as well as STARTTLS extension is shown in '../examples/ssl-smtp-{server,client}'.
Please be aware that ssl-smtp-server is only a test for ssl-smtp-client

CAUTION: ssl-echo-server and ssl-smtp-server depend on a "certificate.pem" and
"key.pem" in the current working directory. In order to try them, go to
'examples/ssl-echo-server' and run '_build/bin/ssl-echo | smtp-server'.

This code was tested (by using the examples) with openssl 3.6.3 on macOS 26.5.2.

Build Notes
===========

In general `deft build -a` should build correctly but if you see an error stating that
`pkg-config` wasn't found you may need to install it in order for Open Dylan to figure
out where your OpenSSL library is installed.  On Linux `sudo apt install pkg-config`.

Documentation
=============

TBD
