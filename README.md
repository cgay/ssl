*****************************
ssl - A Dylan OpenSSL Wrapper
*****************************

This package provides a Dylan wrapper for OpenSSL and interfaces to make secure sockets
work with the Open Dylan "network" library.

Build Notes
===========

In general `deft build -a` should build correctly but if you see an error stating that
`pkg-config` wasn't found you may need to install it in order for Open Dylan to figure
out where your OpenSSL library is installed.  On Linux `sudo apt install pkg-config`.

Documentation
=============

TBD
