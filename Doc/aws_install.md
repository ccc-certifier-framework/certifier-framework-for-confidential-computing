# Instructions for installing in AWS


This is guidance for installing the Certifier on AWS instances.  This is a
"quick start guide" and you should not have to consult other instructions,
you can just "copy and paste" these.  For Amazon, we focus on "EC instances"
and so we really only care about vm_model_tools, which help enforce VM-wide
protection barriers (See CERTIFIER_ROOT/vm_model_tools/examples/scenario1,
for complete instructions.)

These instructions are not foolproof.  Most of the issues we've encountered are
related to differences in the provisioned VM.  The instructions worked "ab initio"
on a Ubuntu instance on AWS where I was able to test.  Again, see the note at the end of
this document if you encounter issues, especially related to steps 1 and 2 below.

After creating an Ubuntu AWS instance and sshing into it,
proceed as follows.


## Step 1 - Install the development tools:

```shell
	sudo apt update -y
	sudo apt upgrade
	sudo apt install "Development Tools"
	sudo apt install g++
```

Install the additional development tools as follows (This is required):

```shell
	sudo apt install -y clang-format libgtest-dev libgflags-dev openssl libssl-dev protobuf-compiler protoc-gen-go golang-go cmake uuid-dev
```

Install the static checking tool, if needed:

```shell
	sudo apt install -y cppcheck
```

## Step 2 Install tools for swigging

This step is not needed for vm_model_tools and you should skip it.  It may be useful in rare cases
later but can cause problems.

```shell
	sudo apt install -y python3 pylint
	pip install pytest
	sudo apt install -y swig
	sudo apt install -y python3-protobuf
```

## Step 3 - Get certifier repository

Download the Certifier Framework from github.

```shell
	mkdir src
	cd src
	mkdir github.com
	cd github.com
	git clone https://github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing.git
	cd certifier-framework-for-confidential-computing
```

## Step 4 - Set the Certifier root directory

The actual full directory name is VM dependant.  FOr the Ubuntu instance I used, the following works.

```shell
	export CERTIFIER_ROOT="/home/ubuntu/src/github.com/certifier-framework-for-confidential-computing"
```

## Step 5 - Compile certifier tests and run them

To Compile the certifier tests:

```shell
	cd $CERTIFIER_ROOT
	cd src
	make -f certifier_tests.mak
```

Now, run the tests:

```shell
	./certifier_tests.exe --print_all=true
```

## Step 6 - Build the vm_model_tools and run the standard tests

Now let's build the vm_model_tools and examples.  Note that the tests must run as
root because they install a new device driver and the driver requires root access
in use.

```shell
	cd $CERTIFIER_ROOT
	sudo bash
	export CERTIFIER_ROOT="/home/ubuntu/src/github.com/certifier-framework-for-confidential-computing"
	export EXAMPLE_DIR=$CERTIFIER_ROOT/vm_model_tools/examples/scenario1
	cd $EXAMPLE_DIR
	./run-test-scenario1.sh  -tt simulated -bss 1 -ccf 1 -pk 1 -loud 1
```

## Notes on installation variations (especially related to development tools)

The instructions above were tested on a standard AWS VM image but differences between Linux VM's
have caused problems.

In some VM's, the base VM contains the basic development tools already (The stuff installed by
build-essential" below.

If the command 'sudo apt install "Development Tools"' fails, there are numerous alternatives.
For example, on Red Hat distributions "yum" replaces apt.  In the future I'll try and find a set of
commands that run on all VM's, if such a thing is possible.  In the measwhile, here is some first aid.

If 'sudo apt install "Development Tools"' fails, try:

```shell
sudo dnf update
sudo dnf group install "Development Tools"
```
If that doesn't work, try installing the build essential tools and some individual tools.
Build-essentials is supposed to include the base gcc, make and things you need to build.

```shell
sudo apt install build-essential
sudo apt install g++
sudo apt install git
sudo apt install cmake
sudo apt install vim
```

Stay tuned for definitive alternatives.  Please let me know if you encounter problems or have suggestions.
