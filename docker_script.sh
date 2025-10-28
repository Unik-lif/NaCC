mkdir riscv-docker

apt-get update
apt-get install -y git pkg-config libseccomp2 libseccomp-dev wget vim make build-essential cmake

# First we build the golang toolchain
wget https://golang.google.cn/dl/go1.23.9.linux-riscv64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.9.linux-riscv64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
source ~/.profile

# download and install runc
cd ~/riscv-docker
git clone --branch v1.3.2 https://github.com/opencontainers/runc.git
cd runc
make && make install

# download and install containerd
cd ~/riscv-docker
git clone --branch v2.1.4 https://github.com/containerd/containerd.git
cd containerd
make BUILDTAGS="no_btrfs"
make install

# download and install tini
cd ~/riscv-docker
git clone https://github.com/krallin/tini.git
cd tini
export CFLAGS="-DPR_SET_CHILD_SUBREAPER=36 -DPR_GET_CHILD_SUBREAPER=37"
cmake . && make
cp tini-static /usr/local/bin/docker-init


# setup the go module, and build moby docker.
cd 
mkdir -p ~/go/src/github.com/docker
cd ~/go/src/github.com/docker
git clone --branch v28.4.0 https://github.com/moby/moby.git docker
cd docker
cp ./contrib/dockerd-rootless.sh /usr/local/bin
./hack/make.sh binary
cp bundles/binary-daemon/dockerd /usr/local/bin/dockerd

# build docker cli
cd ~/go/src/github.com/docker
git clone --branch v28.5.0 https://github.com/docker/cli.git
cd cli
DISABLE_WARN_OUTSIDE_CONTAINER=1 GO111MODULE=off make
cp ./build/docker-linux-riscv64 /usr/local/bin
ln -sf /usr/local/bin/docker-linux-riscv64 /usr/local/bin/docker


# disable userland-proxy, which is not important to run our nacc project.
mkdir -p /etc/docker
echo '{
  "userland-proxy": false
}' | tee /etc/docker/daemon.json > /dev/null


# Service setup
cat << EOF | tee -a /etc/systemd/system/containerd.service
[Unit]
Description=containerd container runtime
Documentation=https://containerd.io
After=network.target

[Service]
ExecStartPre=-/sbin/modprobe overlay
ExecStart=/usr/local/bin/containerd
KillMode=process
Delegate=yes
LimitNOFILE=1048576
# Having non-zero Limit*s causes performance problems due to accounting overhead
# in the kernel. We recommend using cgroups to do container-local accounting.
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity

[Install]
WantedBy=multi-user.target
EOF

cat << EOF | tee -a /etc/systemd/system/docker.service
[Unit]
Description=Docker Application Container Engine
Documentation=https://docs.docker.com
BindsTo=containerd.service
After=network-online.target firewalld.service containerd.service
Wants=network-online.target
Requires=docker.socket

[Service]
Type=notify
# the default is not to use systemd for cgroups because the delegate issues still
# exists and systemd currently does not support the cgroup feature set required
# for containers run by docker
ExecStart=/usr/local/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
ExecReload=/bin/kill -s HUP $MAINPID
TimeoutSec=0
RestartSec=2
Restart=always

# Note that StartLimit* options were moved from "Service" to "Unit" in systemd 229.
# Both the old, and new location are accepted by systemd 229 and up, so using the old location
# to make them work for either version of systemd.
StartLimitBurst=3

# Note that StartLimitInterval was renamed to StartLimitIntervalSec in systemd 230.
# Both the old, and new name are accepted by systemd 230 and up, so using the old name to make
# this option work for either version of systemd.
StartLimitInterval=60s

# Having non-zero Limit*s causes performance problems due to accounting overhead
# in the kernel. We recommend using cgroups to do container-local accounting.
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity

# Comment TasksMax if your systemd version does not supports it.
# Only systemd 226 and above support this option.
TasksMax=infinity

# set delegate yes so that systemd does not reset the cgroups of docker containers
Delegate=yes

# kill only the docker process, not all processes in the cgroup
KillMode=process

[Install]
WantedBy=multi-user.target
EOF

cat << EOF | tee -a /etc/systemd/system/docker.socket
[Unit]
Description=Docker Socket for the API

[Socket]
# If /var/run is not implemented as a symlink to /run, you may need to
# specify ListenStream=/var/run/docker.sock instead.
ListenStream=/run/docker.sock
SocketMode=0660
SocketUser=root
SocketGroup=root

[Install]
WantedBy=sockets.target
EOF

# Service Enabling
systemctl enable docker.socket
systemctl enable docker
systemctl enable containerd