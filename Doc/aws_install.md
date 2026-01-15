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

Install tools for swigging, etc if needed:

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

Compile certifier tests as a check:

```shell
	export CERTIFIER_ROOT="/home/ubuntu/src/github.com/certifier-framework-for-confidential-computing"
	cd $CERTIFIER_ROOT
	cd src
	make -f certifier_tests.mak
```

Run the tests:

```shell
	./certifier_tests.exe --print_all=true
```

