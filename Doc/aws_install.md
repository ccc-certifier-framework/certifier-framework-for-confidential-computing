# Instructions for installing in AWS


After creating an Ubuntu AWS instance and sshing into it,
proceed as follows.


Install the development tools:

```shell
	sudo apt update -y
	sudo apt upgrade
	sudo apt install "Development Tools"
	sudo apt install g++
```

Install the additional development tools as follows:

```shell
	sudo apt install -y clang-format libgtest-dev libgflags-dev openssl libssl-dev protobuf-compiler protoc-gen-go golang-go cmake uuid-dev
```

Install the static checking tool, if needed:

```shell
	sudo apt install -y cppcheck
```

(Skip this sstep) Install tools for swigging, etc, if needed:

```shell
	sudo apt install -y python3 pylint
	pip install pytest
	sudo apt install -y swig
	sudo apt install -y python3-protobuf
```

Get certifier repository:

```shell
	mkdir src
	cd src
	mkdir github.com
	cd github.com
	git clone https://github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing.git
	cd certifier-framework-for-confidential-computing
```

Set the Certifier root directory:

```shell
	export CERTIFIER_ROOT="/home/ubuntu/src/github.com/certifier-framework-for-confidential-computing"
```

Compile certifier tests as a check:

```shell
	cd $CERTIFIER_ROOT
	cd src
	make -f certifier_tests.mak
```

Run the tests:

```shell
	./certifier_tests.exe --print_all=true
```

Now let's build the vm_model_tools and examples:

```shell
	cd $CERTIFIER_ROOT
	sudo bash
	export CERTIFIER_ROOT="/home/ubuntu/src/github.com/certifier-framework-for-confidential-computing"
	export EXAMPLE_DIR=$CERTIFIER_ROOT/vm_model_tools/examples/scenario1
	cd $EXAMPLE_DIR
	./run-test-scenario1.sh  -tt simulated -bss 1 -ccf 1 -pk 1 -loud 1
```
