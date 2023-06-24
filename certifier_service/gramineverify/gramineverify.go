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

package gramineverify

/*
#cgo CFLAGS: -g -Wall -I../graminelib
#cgo LDFLAGS: -L../graminelib -lgramineverify -Wl,-rpath=graminelib:../../certifier_service/graminelib/:../../../certifier_service/graminelib
#include "gramine_verify.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func GramineVerify(what_to_say []byte, attestation []byte) ([]byte, error) {
	what_to_say_ptr := C.CBytes(what_to_say)
	defer C.free(what_to_say_ptr)
	attestation_ptr := C.CBytes(attestation)
	defer C.free(attestation_ptr)
	measurementSize := C.int(256)
	measurementOut := C.malloc(C.ulong(measurementSize))
	defer C.free(unsafe.Pointer(measurementOut))
	ret := C.graminelib_Verify(C.int(len(what_to_say)), (*C.uchar)(what_to_say_ptr),
		C.int(len(attestation)), (*C.uchar)(attestation_ptr),
		&measurementSize, (*C.uchar)(measurementOut))
	if !ret {
		return nil, fmt.Errorf("gramine_Verify failed")
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
 *  outMeasurement, err := gramineverify.GramineVerify(whattosay, attestation)
 *  if err != nil {
 *          fmt.Printf("GramineVerify failed: %s\n", err.Error())
 *  }
 *  fmt.Printf("Measurement length: %d\n", len(outMeasurement));
 */
