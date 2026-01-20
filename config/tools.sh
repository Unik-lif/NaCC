#!/bin/bash
apt update
apt install pkg-config libseccomp2 libseccomp-dev git make wget build-essential -y
wget https://golang.google.cn/dl/go1.23.10.linux-riscv64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.10.linux-riscv64.tar.gz
echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.bashrc
source ~/.bashrc


