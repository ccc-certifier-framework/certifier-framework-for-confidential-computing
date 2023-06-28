# Preliminary Keystone Instructions

## Shim Only

Install requirements as per `INSTALL.md` in Certifier root.

### Example App

See `temporary_instructions.txt`.

### Tests

No dependencies on Keystone, can build on any architecture and with any compiler.

`cd certifier/src/keystone && make -f shim_test.mak all`

## Keystone Setup

Note: this is NOT needed for shim.

### Start Qemu

We will download and run a Docker container that has Keystone and its tooling fully set up and compiled: RISC-V cross-compiler, Keystone driver as well as modified Qemu, Linux, etc. Then, we will launch Qemu.

In other sections, from another terminal, we will compile and `scp` in the desired Certifier app.

1. `docker pull keystoneenclaveorg/keystone:master`
2. `docker run -it --entrypoint /bin/bash keystoneenclaveorg/keystone:dev --volume ABS_CERTIFIER_PATH:/certifier`
   1. `ABS_CERTIFIER_PATH` is the absolute path to the certifier directory on your native file system. This allows both the Docker container and your computer to read and write to the entire directory, and for changes to this directory to be persistent.
   2. You may start a `tmux` session here, or create a new terminal to the Docker container later.
3. `cd /keystone/build && ./scripts/run-qemu.sh`
   1. Keystone provides a bash script to launch a RISC-V QEMU machine with a random host `PORT` forwarded to the guest SSH port (22). The port is determined when launching Qemu, and is printed out at the beginning of the script. Note down the `PORT` for SSH into the emulated machine.
4. Username: `root` Password: `sifive`
5. `insmod keystone-driver.ko`

### Certifier Dependencies

Note: Some OpenSSL Crypto and Certifier helpers use `dl`, while the certifier does not support dynamic linking, so support may not be 100%.

Download the dependencies distributed by the Keystone team:

```bash
export RISCV_SUPPORT=CERTIFIER_DIRECTORY/src/keystone/packages
mkdir -p $RISCV_SUPPORT && cd $RISCV_SUPPORT
wget https://github.com/keystone-enclave/certifier-deps/releases/download/v0.1/packages.tar.gz
tar -xf packages.tar.gz
```

### Maintaining Certifier Dependencies

Useful only if the versions in the above section are unsatisfactory.

Any libraries linked in must be RISC-V, static, and cannot use `pthread` to be supported by Keystone as of Summer 2023.

#### Protobuf

Official builds of Protobuf conform to the requirements, so we can simply download it.

In principle you could download RISC-V static `libprotobuf` from any source, but the easiest way we've found is to use a package manager from inside a RISC-V machine/ virtual machine. Do the distro-equivalent of this Fedora command that downloads the static library including its dependencies:

```bash
mkdir packages && cd packages
dnf download protobuf-static --resolve
# extract is rpm:
rpm2cpio YOUR_RPM.rpm | cpio -idmv
usr/bin/protoc --version # note down the PROTOBUF_VERSION, in the form of 3.11.4
```

Then, find the `.a` static libraries and the `include` headers. Copy these to either to `RISCV_SUPPORT`.

Next, we need to get the platform-native `protoc` to compile `.proto` files to `C++`. We need to get the version matching the protobuf libraries we got -- `PROTOBUF_VERSION` from above. We can download from Google's official released. In your native machine:

```bash
export PROTOBUF_VERSION="3.11.4"
wget https://github.com/protocolbuffers/protobuf/releases/download/v$PROTOBUF_VERSION/protoc-$PROTOBUF_VERSION-linux-x86_64.zip
unzip protoc-$PROTOBUF_VERSION-linux-x86_64.zip -d . && rm protoc-$PROTOBUF_VERSION-linux-x86_64.zip
bin/protoc --version # check that this matches
```

#### OpenSSL

We have to compile from source because the standard version uses `pthread`. In a RISC-V machine/ virtual machine:

```bash
# git clone ???
# build with correct flags
# copy out the correct things
```

## Real Keystone

All of these will be in a terminal to the Docker container separate from where Qemu is running. You can open one with an IDE feature, `tmux`, or the below steps.

```bash
docker ps # find the hash of your Keystone container
docker -it CONTAINER_HASH /bin/bash
```

### Programmer-side

#### Example App

Note: Makefile not yet written.

Same as `temporary_instructions.txt`, but using the RISC-V real Keystone makefile.

#### Tests

`cd /certifier/src/keystone && make -f real_test.mak all`

#### API Only App

`cd /certifier/src/keystone/api_only_app && make -f api_only.mak all`

### Host-side

Continuing from programmer-side for testing end-to-end.

1. `mkdir build && cd build && cmake ..`
2. Copy desired app as `./keystone_app.exe`
   1. `cp ../../sample_apps/simple_app_under_keystone/?????todo ./keystone_app.exe`
   2. `cp ../riscv64/keystone_test.exe ./keystone_app.exe`
   3. `cp ../api_only_app/api_only_app.exe ./keystone_app.exe`
3. `make keystone_app.exe-package`
4. `scp -i /keystone/build/overlay/root/.ssh/id_rsa -P PORT certifier.ke root@localhost:./`
   1. `PORT` from Qemu section above.
5. Back in Qemu: `./certifier.ke`
