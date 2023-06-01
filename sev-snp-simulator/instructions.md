# Steps to build and test the SEV-SNP simulator

```shell
make clean
make
make keys
make insmod
cd test
make
sudo ./sev-test
```

If you have to re-run these steps, do `$ make rmmod` before re-running
`$ make insmod`.
