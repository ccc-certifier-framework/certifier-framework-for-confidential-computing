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
	"fmt"
	"unsafe"
)

func TpmVerify(quoteCert []byte, serializedTpmAttestation []byte) ([]byte, error) {

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
		return nil, fmt.Errorf("TpmVerify failed")
	}
	outMeasurement := C.GoBytes(unsafe.Pointer(measurementOut),
		C.int(measurementSize))
	return outMeasurement, nil
}

/*
 *  Sample usage:
 *
 *  attestation, err := os.ReadFile("attestation.bin")
 *  if err != nil {
 *          fmt.Printf("Failed to read attestation file: %s\n", err.Error())
 *  }
 *  whattosay, err := os.ReadFile("whattosay.bin")
 *  if err != nil {
 *          fmt.Printf("Failed to read whattosay file: %s\n", err.Error())
 *  }
 *  outMeasurement, err := tpmverify.TpmVerify(whattosay, attestation)
 *  if err != nil {
 *          fmt.Printf("TpmVerify failed: %s\n", err.Error())
 *  }
 *  fmt.Printf("Measurement length: %d\n", len(outMeasurement));
 */
