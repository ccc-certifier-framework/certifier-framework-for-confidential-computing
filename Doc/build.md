# Building the Certifier Framework and sample apps from source

## On Linux

```shell
# Install v1.11.0-3
sudo apt-get install googletest

# OpenSSL 3.0.2
sudo apt-get install openssl

# libSSL-dev v3.0.2
sudo apt-get install -y libssl-dev

```
## On Mac/OSX

```shell
brew install protobuf@3

# sudo ln -s /usr/local/opt/protobuf@3/lib/libprotobuf.a /usr/local/lib/libprotobuf.a
# sudo ln -s /usr/local/Cellar/protobuf@3/3.20.3/bin/protoc /usr/local/bin/protoc
sudo ln -s /usr/local/opt/protobuf@3/bin/protoc /usr/local/bin/protoc

sudo ln -s /usr/local/Cellar/protobuf@3/3.20.3/include/google /usr/local/include/google
```


```shell
brew install googletest
brew install gflags
brew link --overwrite protobuf@3

brew install protoc-gen-go
brew install openssl
brew install libssl-dev
brew install swig
```

## Uninstall instructions

```
brew uninstall --ignore-dependencies openssl
```
