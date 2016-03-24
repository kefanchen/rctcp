#!/bin/bash
MTCP_ROOT=$(pwd)/../
echo MTCP_ROOT

sudo ifconfig p1p1 down
sudo ifconfig p1p2 down
clear

#compile the dpdk
cd $MTCP_ROOT/scripts/
sudo ./setup.sh

#configure mtcp
rm -rf $MTCP_ROOT/dpdk/*
ln -s $MTCP_ROOT/dpdk-2.0.0/x86_64-native-linuxapp-gcc/lib $MTCP_ROOT/dpdk/lib
ln -s $MTCP_ROOT/dpdk-2.0.0/x86_64-native-linuxapp-gcc/include $MTCP_ROOT/dpdk/include
cd $MTCP_ROOT
./configure --with-dpdk-lib=$MTCP_ROOT/dpdk

#make mtcp
cd $MTCP_ROOT/mtcp/src
make

#make util
cd $MTCP_ROOT/util
make

#set ip
cd $MTCP_ROOT/dpdk-2.0.0/tools
echo ""
echo ""
echo "##########################################"
echo "set ip, give the last number, for example:"
echo "4 for 10.0.0.4 and 10.0.1.4"
#read ip
ip=4
sudo ./setup_iface_single_process.sh $ip

#make example
cd $MTCP_ROOT/apps/example
make

#make test
cd $MTCP_ROOT/apps/test
make

