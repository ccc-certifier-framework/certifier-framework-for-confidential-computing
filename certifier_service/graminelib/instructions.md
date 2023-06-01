Instructions for building gramine certifier C to Go interfaces
==============================================================

$CERTIFIER_PROTOTYPE is the top level directory for the certifier repository.

1. Step 1: Download MbedTLS
```
cd $CERTIFIER_PROTOTYPE/certifier_service/graminelib
./configureMbedTLS
```

2. Build the library
```
make
```

To cleanup:
```
make clean
make distclean
```

3. Build simpleserver:
```
cd $CERTIFIER_PROTOTYPE/certifier_service
go build simpleserver.go
```
