# Instructions for building Gramine certifier C to Go interfaces

$CERTIFIER_PROTOTYPE is the top level directory for the certifier repository.

## Step 1: Download MbedTLS
```shell
cd $CERTIFIER_PROTOTYPE/certifier_service/graminelib
./configureMbedTLS
```

## Step 2. Build the library
```shell
make
```

## To cleanup:
```shell
make clean
make distclean
```

## Step 3. Build simpleserver:
```shell
cd $CERTIFIER_PROTOTYPE/certifier_service
go build simpleserver.go
```
