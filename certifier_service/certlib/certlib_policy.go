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

package certlib

import (
	// "bytes"
	// "errors"
	// "strings"
	// "time"
	"fmt"
	"google.golang.org/protobuf/proto"
	"io/ioutil"
	"os"

	certprotos "github.com/vmware-research/certifier-framework-for-confidential-computing/certifier_service/certprotos"
)

func PolicyStoreNumEntries(ps *certprotos.PolicyStoreMessage) int {
	return len(ps.Entries)
}

func PrintPolicyStoreEntry(e *certprotos.PolicyStoreEntry) {
	fmt.Printf("Tag: %s, Type: %s, Value: ", e.GetTag(), e.GetType())
	PrintBytes(e.GetValue())
	fmt.Printf("\n")
}

func NewPolicyStoreEntry(tag string, valueType string, value []byte) *certprotos.PolicyStoreEntry {
	e := new(certprotos.PolicyStoreEntry)
	e.Tag = &tag
	e.Type = &valueType
	e.Value = value
	return e
}

func NewPolicyStore(maxEnts int) *certprotos.PolicyStoreMessage {
	ps := new(certprotos.PolicyStoreMessage)
	me := int32(maxEnts)
	ps.MaxEnts = &me
	return ps
}

func PrintPolicyStore(ps *certprotos.PolicyStoreMessage) {
	fmt.Printf("Maximum Entries: %d, current entries: %d\n", int(ps.GetMaxEnts()), len(ps.Entries))
	for i := 0; i < len(ps.Entries); i++ {
		fmt.Printf("   ")
		PrintPolicyStoreEntry(ps.Entries[i])
	}
}

func FindPolicyStoreEntry(ps *certprotos.PolicyStoreMessage, tag string, valueType string) int {
	for i := 0; i < len(ps.Entries); i++ {
		if ps.Entries[i].GetTag() == tag && ps.Entries[i].GetType() == valueType {
			return i
		}
	}
	return -1
}

func InsertOrUpdatePolicyStoreEntry(ps *certprotos.PolicyStoreMessage, tag string, valueType string, value []byte) bool {
	ent := FindPolicyStoreEntry(ps, tag, valueType)
	if ent >= 0 {
		ps.Entries[ent].Value = value
		return true
	}
	if len(ps.Entries) >= int(ps.GetMaxEnts()) {
		return false
	}
	pse := NewPolicyStoreEntry(tag, valueType, value)
	ps.Entries = append(ps.Entries, pse)
	return true
}

func PolicyStoreDeleteEntry(ent int) {
}

func SavePolicyStore(ps *certprotos.PolicyStoreMessage, fileName string) bool {
	serializedStore, err := proto.Marshal(ps)
	if err != nil {
		return false
	}
	// Todo: Encrypt the store
	if ioutil.WriteFile(fileName, serializedStore, 0666) != nil {
		return false
	}
	return true
}

func RecoverPolicyStore(fileName string, ps *certprotos.PolicyStoreMessage) bool {
	// Todo: Decrypt the store
	serializedStore, err := os.ReadFile(fileName)
	if err != nil {
		return false
	}
	err = proto.Unmarshal(serializedStore, ps)
	if err != nil {
		return false
	}
	
	return true
}

//  --------------------------------------------------------------------

