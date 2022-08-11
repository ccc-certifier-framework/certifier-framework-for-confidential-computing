# Install Certifier (Ubuntu 20.04)


### Setup Environment variables 
```
git clone https://github.com/vmware-research/certifier-framework-for-confidential-computing.git
export CERTIFIER=`pwd`/certifier-framework-for-confidential-computing
export CERTIFIER_PROTOTYPE=$CERTIFIER
export EXAMPLE_DIR=$CERTIFIER_PROTOTYPE/sample_apps
```

### Install Dependencies
```
sudo apt install libgtest-dev libgflags-dev
```

We note that the versioning of `protobuf` and `golang` matters. One shall not use the distribution directly `apt`-ed from Ubuntu. 

Install the latest protobuf from source by 
```
sudo apt install autoconf automake libtool curl make g++ unzip
git clone https://github.com/protocolbuffers/protobuf.git
cd protobuf
git submodule update --init --recursive
./autogen.sh && ./configure
 make -j$(nproc)  &&  sudo make install
 sudo ldconfig # refresh shared library cache.
``` 
the detailed installation procedure can be found https://github.com/protocolbuffers/protobuf/blob/main/src/README.md. 

Install the latest `golang` by  
```
sudo apt install wget 
wget https://go.dev/dl/go1.18.4.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.18.4.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin && export PATH=$PATH:$(go env GOPATH)/bin
rm go1.18.4.linux-amd64.tar.gz
```

The protobuf compiler(protoc) for golang is installed by 
```
go get github.com/golang/protobuf/proto
go get google.golang.org/protobuf/cmd/protoc-gen-go
```

Ensure OpenSSL library and OpenSSL headers are installed or install by
```
sudo apt install openssl
sudo apt install libssl-dev
```
Current tests on Ubuntu are with OpenSSL 1.1.1f.

### Compile Certifier Library 
The certifier library can be compiled by 
```
 cd $CERTIFIER/src
 make -f certifier.mak

cd $CERTIFIER/utilities
make -f cert_utility.mak
make -f policy_utilities.mak
```


### Build the Certifier Service 

1. Compile the protobuf required by certifier service by 
```
 cd $CERTIFIER/certifier_service/certprotos
 protoc --go_opt=paths=source_relative --go_out=. --go_opt=Mcertifier.proto= ./certifier.proto
```

2. Install the certifier as go library by
```
go install  github.com/jlmucb/crypto@latest
# TODO: this is a workaround to an existing path issue 
mkdir -p $(go env GOPATH)/src/github.com/jlmucb/crypto/v2
sudo cp -r $CERTIFIER $(go env GOPATH)/src/github.com/jlmucb/crypto/v2
```

3. Build the simple server
```
 cd $CERTIFIER/certifier_service
 go build simpleserver.go
```
If showing error of `go.mod not found`, run `go env -w GO111MODULE=off` before building. 


### Run `sample_app`

To run sample application, follow the README in sample_app or directly run 
```
cd $EXAMPLE_DIR/simple_app
chmod +x ./script
./script
```

