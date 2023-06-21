# Instructions for building CCA certifier C to Go interfaces

$CERTIFIER_PROTOTYPE is the top level directory for the Certifier repository.

## Build the library
```shell
make
```

### To cleanup:
```shell
make clean
make distclean
```

##. Build simpleserver:
```shell
cd $CERTIFIER_PROTOTYPE/certifier_service/certprotos
protoc --go_opt=paths=source_relative --go_out=. --go_opt=M=certifier.proto ./certifier.proto

cd ../
go build simpleserver.go
```
