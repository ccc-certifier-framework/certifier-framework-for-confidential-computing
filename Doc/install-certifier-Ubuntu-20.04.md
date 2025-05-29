# Install Certifier (Ubuntu 20.04)

### Setup Environment variables 

```bash
cd ~/Projects
git clone https://github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing.git

export CERTIFIER=~/Projects/certifier-framework-for-confidential-computing
export EXAMPLE_DIR=$CERTIFIER/sample_app
```

### Install Dependencies

**Note**: The UUID library is required for compilation but was missing from the original documentation.

```bash
sudo apt update
sudo apt install libgtest-dev libgflags-dev uuid-dev
```

We note that the versioning of `protobuf` and `golang` matters. One shall not use the distribution directly `apt`-ed from Ubuntu. 

Install the latest protobuf from source by 
```bash
sudo apt install autoconf automake libtool curl make g++ unzip
git clone https://github.com/protocolbuffers/protobuf.git
cd protobuf
git submodule update --init --recursive
./autogen.sh && ./configure
make -j$(nproc) && sudo make install
sudo ldconfig # refresh shared library cache.
``` 
The detailed installation procedure can be found https://github.com/protocolbuffers/protobuf/blob/main/src/README.md. 

Install the latest `golang` by  
```bash
sudo apt install wget 
wget https://go.dev/dl/go1.18.4.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.18.4.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin && export PATH=$PATH:$(go env GOPATH)/bin
rm go1.18.4.linux-amd64.tar.gz
```

**Updated Go Protobuf Installation**: The `go get` commands are deprecated. Use `go install` instead:
```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

**Alternative method** (if the above doesn't work, as referenced in the grpc.io quickstart):
```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
```

Ensure OpenSSL library and OpenSSL headers are installed or install by
```bash
sudo apt install openssl libssl-dev
```
Current tests on Ubuntu are with OpenSSL 1.1.1f.

### Compile Certifier Library 

The certifier library can be compiled by 
```bash
cd $CERTIFIER/src
make -f certifier.mak

cd $CERTIFIER/utilities
make -f cert_utility.mak
make -f policy_utilities.mak
```

### Build the Certifier Service 

1. Compile the protobuf required by certifier service by 
```bash
cd $CERTIFIER/certifier_service/certprotos
protoc --go_opt=paths=source_relative --go_out=. --go_opt=Mcertifier.proto= ./certifier.proto
```

2. Install the certifier as go library by
```bash
go install github.com/jlmucb/crypto@latest
# TODO: this is a workaround to an existing path issue 
mkdir -p $(go env GOPATH)/src/github.com/jlmucb/crypto/v2
sudo cp -r $CERTIFIER $(go env GOPATH)/src/github.com/jlmucb/crypto/v2
```

3. Build the simple server
```bash
cd $CERTIFIER/certifier_service
go build simpleserver.go
```
If showing error of `go.mod not found`, run `go env -w GO111MODULE=off` before building. 

### Run `sample_app`

To run sample application, follow the README in sample_app or directly run 
```bash
cd $EXAMPLE_DIR
chmod +x ./script
./script
```

## Troubleshooting

### Common Issues:

1. **UUID library missing**: If you get `fatal error: uuid/uuid.h: No such file or directory`, ensure you've installed `uuid-dev`:
   ```bash
   sudo apt install uuid-dev
   ```

2. **Go protobuf installation issues**: The original `go get` commands are deprecated. Use the updated `go install` commands provided above, or refer to the official gRPC Go quickstart guide at https://grpc.io/docs/languages/go/quickstart/

3. **Protobuf version conflicts**: Make sure to install protobuf from source rather than using the Ubuntu package to avoid version mismatches.