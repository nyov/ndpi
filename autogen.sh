#!/bin/sh

autoreconf -ivf
(cd example/third-party/json-c && autoreconf -ivf)
./configure
