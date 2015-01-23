#!/bin/bash

wget http://tinkerpop.com/downloads/rexster/rexster-server-2.6.0.zip
unzip rexster-server-2.6.0.zip
rm rexster-server-2.6.0.zip
mv rexster-server-2.6.0 rexster-server

cp ./rexster-config/rexster-tinkergraph.xml ./rexster-server/config/rexster.xml