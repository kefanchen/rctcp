#!/bin/bash
MTCP_ROOT=$(pwd)/../
cd $MTCP_ROOT/dpdk-2.0.0/tools/
sudo ./setup_iface_single_process.sh $1

