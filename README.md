tcptracelib
===========
This is an experiment to see if parts of tcptrace can be made into a
library.

Current status:
===============
refining API
working on output export

Done:
=====
libtcptrace now independent of tcptrace client
most global variables removed
packet processing loop factored out into process.c
updated to use automake/libtool
options selection via option functions in options.c

