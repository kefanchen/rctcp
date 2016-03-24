#!/bin/bash
MTCP_ROOT=$(pwd)/../
echo $MTCP_ROOT

#clean mtcp/src
cd $MTCP_ROOT/mtcp/src
make clean

#clean DPDK
cd $MTCP_ROOT/dpdk-2.0.0/
sudo make uninstall
cd $MTCP_ROOT/dpdk/
rm -rf *

#note: Other examples didn't use in this script, so 
#      if you nedd it, add them by yourself
#clean example
cd $MTCP_ROOT/apps/example/
make clean

#clean test
cd $MTCP_ROOT/apps/test/
make clean

#clean util
cd $MTCP_ROOT/util/
make clean

