//  Copyright (c) 2023, VMware Inc, and the Certifier Authors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tpmverify

/*
#cgo CFLAGS: -g -Wall -I../tpmlib
#cgo LDFLAGS: -L../tpmlib -ltpmverify -Wl,-rpath=tpmlib:../../certifier_service/tpmlib/:../../../certifier_service/tpmlib
#include "tpmverify.h"
*/
import "C"
import (
	"unsafe"
	//"fmt"
)

// returns succeed/fail, pcrDigest and bytes describing pcrs
func TpmVerify(quoteCert []byte, serializedTpmAttestation []byte) (bool, []byte, []byte) {

	quote_ptr := C.CBytes(quoteCert)
	defer C.free(quote_ptr)
	attestation_ptr := C.CBytes(serializedTpmAttestation)
	defer C.free(attestation_ptr)
	measurementSize := C.int(256)
	measurementOut := C.malloc(C.ulong(measurementSize))
	defer C.free(unsafe.Pointer(measurementOut))
	pcrSize := C.int(256)
	pcrOut := C.malloc(C.ulong(pcrSize))
	defer C.free(unsafe.Pointer(pcrOut))

	ret := C.tpm_host_verify_attest((C.int)(len(quoteCert)),
		                        (*C.uchar)(quote_ptr),
		                        (C.int)(len(serializedTpmAttestation)),
		                        (*C.uchar)(attestation_ptr),
		                        (*C.int)(&measurementSize),
		                        (*C.uchar)(measurementOut),
		                        (*C.int)(&pcrSize),
		                        (*C.uchar)(pcrOut))
	if !ret {
		return false, nil, nil
	}
	outMeasurement := C.GoBytes(unsafe.Pointer(measurementOut),
		C.int(measurementSize))
	outRegisters:= C.GoBytes(unsafe.Pointer(pcrOut),
		C.int(pcrSize))
	return true, outMeasurement, outRegisters
}


func TpmMakeCredential(hash_alg string,
	quoteKeyName []byte, endorsementCert []byte, credential []byte) (bool, []byte, []byte) {

	aName := C.CString(hash_alg)
	defer C.free(unsafe.Pointer(aName))

	quote_name_ptr := C.CBytes(quoteKeyName)
	defer C.free(quote_name_ptr)
	endorsement_cert_ptr := C.CBytes(endorsementCert)
	defer C.free(endorsement_cert_ptr)
	credential_ptr := C.CBytes(credential)
	defer C.free(credential_ptr)

	credBlobSize := C.int(256)
	credBlobOut := C.malloc(C.ulong(credBlobSize))
	defer C.free(unsafe.Pointer(credBlobOut))
	encryptedSecretSize := C.int(1024)
	encryptedSecretOut := C.malloc(C.ulong(encryptedSecretSize))
	defer C.free(unsafe.Pointer(encryptedSecretOut))

	ret := C.certifier_make_a_credential((*C.char)(aName),
				(C.int)(len(quoteKeyName)),
				(*C.uchar)(quote_name_ptr),
				(C.int)(len(endorsementCert)),
				(*C.uchar)(endorsement_cert_ptr),
				(C.int)(len(credential)),
				(*C.uchar)(credential_ptr),
				(*C.int)(&credBlobSize),
				(*C.uchar)(credBlobOut),
				(*C.int)(&encryptedSecretSize),
				(*C.uchar)(encryptedSecretOut));

	if !ret {
		return false, nil, nil
	}

	outCredBlob:= C.GoBytes(unsafe.Pointer(credBlobOut),
		C.int(credBlobSize))
	outEncryptedSecret := C.GoBytes(unsafe.Pointer(encryptedSecretOut),
		C.int(encryptedSecretSize))
	return true, outCredBlob, outEncryptedSecret
}
