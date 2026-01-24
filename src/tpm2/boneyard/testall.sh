#!/bin/bash
./tpm2_util.exe --command=Flushall
./tpm2_util.exe --command=ReadPcr --pcr_num=7
./tpm2_util.exe --command=Flushall
./tpm2_util.exe --command=KeyCombinedTest --pcr_num=7
./tpm2_util.exe --command=Flushall
./tpm2_util.exe --command=SealCombinedTest --pcr_num=7
./tpm2_util.exe --command=Flushall
./tpm2_util.exe --command=QuoteCombinedTest --pcr_num=7
./tpm2_util.exe --command=Flushall
./tpm2_util.exe --command=ContextCombinedTest --pcr_num=7
./tpm2_util.exe --command=Flushall
./tpm2_util.exe --command=NvCombinedTest --pcr_num=7
./tpm2_util.exe --command=Flushall
./tpm2_util.exe --command=EndorsementCombinedTest --pcr_num=7
./tpm2_util.exe --command=Flushall
./tpm2_util.exe --command=NvCombinedSessionTest --pcr_num=7
./tpm2_util.exe --command=Flushall

openssl x509 -inform DER -in endorsement_cert -purpose -text


