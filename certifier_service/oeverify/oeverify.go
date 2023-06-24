//  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights reserved.
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

package oeverify

/*
#cgo CFLAGS: -g -Wall -I../oelib
#cgo LDFLAGS: -L../oelib -loeverify -Wl,-rpath=oelib:../../certifier_service/oelib/:../../../certifier_service/oelib
#include "oeverify.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func OEHostVerifyEvidence(evidence []byte, endorsements []byte, tcb bool) ([]byte, []byte, error) {
	evidencePtr := C.CBytes(evidence)
	defer C.free(evidencePtr)
	endorsementsPtr := unsafe.Pointer(uintptr(0))
	if endorsements != nil {
		endorsementsPtr = C.CBytes(endorsements)
		defer C.free(endorsementsPtr)
	}

	customClaimOutSize := C.ulong(4096)
	customClaimOut := C.malloc(customClaimOutSize)
	defer C.free(unsafe.Pointer(customClaimOut))
	measurementSize := C.ulong(256)
	measurementOut := C.malloc(measurementSize)
	defer C.free(unsafe.Pointer(measurementOut))
	checkTCB := C.bool(tcb)

	ret := C.oe_host_verify_evidence((*C.uchar)(evidencePtr),
		C.ulong(len(evidence)),
		(*C.uchar)(endorsementsPtr), C.ulong(len(endorsements)),
		(*C.uchar)(customClaimOut), &customClaimOutSize,
		(*C.uchar)(measurementOut), &measurementSize, checkTCB)

	if !ret {
		return nil, nil, fmt.Errorf("oe_host_verify_evidence failed")
	}
	outCustomClaims := C.GoBytes(unsafe.Pointer(customClaimOut),
		C.int(customClaimOutSize))
	outMeasurement := C.GoBytes(unsafe.Pointer(measurementOut),
		C.int(measurementSize))

	return outCustomClaims, outMeasurement, nil
}

/*
 *  Sample usage:
 *
 *  evidence, err := os.ReadFile("evidence.bin")
 *  if err != nil {
 *          fmt.Printf("Failed to read evidence file: %s\n", err.Error())
 *  }
 *  endorsements, err := os.ReadFile("endorsements.pem")
 *  if err != nil {
 *          fmt.Printf("Failed to read endorsements file: %s\n", err.Error())
 *  }
 *  outCustomClaims, outMeasurement, err := oeverify.OEHostVerifyEvidence(evidence, endorsements, false)
 *  if err != nil {
 *          fmt.Printf("OEHostVerifyEvidence failed: %s\n", err.Error())
 *  }
 *  fmt.Printf("Custom Claim length: %d, Measurement length: %d\n", len(outCustomClaims), len(outMeasurement));
 */
