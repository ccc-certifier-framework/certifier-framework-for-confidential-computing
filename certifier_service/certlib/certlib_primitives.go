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

package certlib

/*
#cgo CFLAGS: -g -Wall -I../teelib
#cgo LDFLAGS: -L../teelib -ltee -Wl,-rpath=teelib:../../certifier_service/teelib/:../../../certifier_service/teelib
#include "tee_primitives.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func TEEAttest(enclave_type string, what_to_say []byte) ([]byte, error) {
	what_to_say_ptr := C.CBytes(what_to_say)
	defer C.free(what_to_say_ptr)
	etype := C.CString(enclave_type)
	defer C.free(unsafe.Pointer(etype))
	outSize := C.int(16000)
	out := C.malloc(C.ulong(outSize))
	defer C.free(unsafe.Pointer(out))

	ret := C.tee_Attest(etype, C.int(len(what_to_say)), (*C.uchar)(what_to_say_ptr),
		&outSize, (*C.uchar)(out))
	if !ret {
		return nil, fmt.Errorf("tee_Attest failed")
	}
	evidence := C.GoBytes(unsafe.Pointer(out),
		C.int(outSize))
	return evidence, nil
}

func TEESeal(enclave_type string, enclave_id string, in []byte, outMax int) ([]byte, error) {
	in_ptr := C.CBytes(in)
	defer C.free(in_ptr)
	etype := C.CString(enclave_type)
	defer C.free(unsafe.Pointer(etype))
	eid := C.CString(enclave_id)
	defer C.free(unsafe.Pointer(eid))
	outSize := C.int(outMax)
	out := C.malloc(C.ulong(outSize))
	defer C.free(unsafe.Pointer(out))

	ret := C.tee_Seal(etype, eid, C.int(len(in)), (*C.uchar)(in_ptr),
		&outSize, (*C.uchar)(out))
	if !ret {
		return nil, fmt.Errorf("tee_Seal failed")
	}
	cipher := C.GoBytes(unsafe.Pointer(out),
		C.int(outSize))
	return cipher, nil
}

func TEEUnSeal(enclave_type string, enclave_id string, in []byte, outMax int) ([]byte, error) {
	in_ptr := C.CBytes(in)
	defer C.free(in_ptr)
	etype := C.CString(enclave_type)
	defer C.free(unsafe.Pointer(etype))
	eid := C.CString(enclave_id)
	defer C.free(unsafe.Pointer(eid))
	outSize := C.int(outMax)
	out := C.malloc(C.ulong(outSize))
	defer C.free(unsafe.Pointer(out))

	ret := C.tee_Unseal(etype, eid, C.int(len(in)), (*C.uchar)(in_ptr),
		&outSize, (*C.uchar)(out))
	if !ret {
		return nil, fmt.Errorf("tee_Unseal failed")
	}
	clear := C.GoBytes(unsafe.Pointer(out),
		C.int(outSize))
	return clear, nil
}

func TEESimulatedInit(asn1_policy_cert string, attest_key_file string, measurement_file string, attest_key_signed_claim_file string) error {
	asn1 := C.CString(asn1_policy_cert)
	defer C.free(unsafe.Pointer(asn1))
	attkey := C.CString(attest_key_file)
	defer C.free(unsafe.Pointer(attkey))
	meas := C.CString(measurement_file)
	defer C.free(unsafe.Pointer(meas))
	attkeyclaim := C.CString(attest_key_signed_claim_file)
	defer C.free(unsafe.Pointer(attkeyclaim))

	ret := C.tee_Simulated_Init(asn1, attkey, meas, attkeyclaim)
	if !ret {
		return fmt.Errorf("tee_Simulated_Init failed")
	}
	return nil
}
