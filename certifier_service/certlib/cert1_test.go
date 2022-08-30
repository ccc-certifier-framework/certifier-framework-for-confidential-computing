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
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"fmt"
	"io"
	"os"
	"time"
	"testing"

	"github.com/golang/protobuf/proto"
	certprotos "github.com/jlmucb/crypto/v2/certifier-framework-for-confidential-computing/certifier_service/certprotos"
)

func TestEntity(t *testing.T) {
	fmt.Print("\nTestEntity\n")
	m:= make([]byte, 32)
	for i := 0; i < 32; i++ {
		m[i] = byte(i)
	}
	a := MakeMeasurementEntity(m)
	if a == nil {
		fmt.Print("cant allocate\n")
		t.Errorf("MakeMeasurementEntity fails")
	}

	PrintEntityDescriptor(a)
	if bytes.Equal(m, a.GetMeasurement()) {
		fmt.Printf("Measurements the same\n")
	} else {
		fmt.Printf("Measurements different\n")
	}

	fmt.Printf("\nTime now   : ")
	tn := TimePointNow()
	PrintTimePoint(tn)
	fmt.Printf("\n")
	fmt.Printf("Time future: ")
	tf := TimePointPlus(tn, 365 * 86400)
	PrintTimePoint(tf)
	fmt.Printf("\n")
	if CompareTimePoints(tn, tf) != (-1) {
		t.Errorf("Comparetime fails")
	}
	st := TimePointToString(tf)
	tf2:= StringToTimePoint(st)
	fmt.Printf("%s, ", st)
	PrintTimePoint(tf2)
	fmt.Printf("\n")
	if CompareTimePoints(tf2, tf) != 0 {
		t.Errorf("string conversions fail")
	}
}

func TestDominance(t *testing.T) {
	fmt.Print("\nTestDominance\n")

	printAll := true

	root := PredicateDominance {
		Predicate:  "is-trusted",
		FirstChild: nil,
		Next: nil,
	}
	if !InitDominance(&root) {
		t.Error("Failed InitDominance")
	}
	if printAll {
		fmt.Printf("\nDominance tree\n")
		PrintDominanceTree(0, &root)
	}

	if !Dominates(&root, "is-trusted", "is-trusted") {
		t.Error("is-trusted fails")
	}
	if !Dominates(&root, "is-trusted", "is-trusted-for-attestation") {
		t.Error("is-trusted-for-attestation fails")
	}
	if !Dominates(&root, "is-trusted", "is-trusted-for-authentication") {
		t.Error("is-trusted-for-attestation fails")
	}
	if Dominates(&root, "is-trusted", "is-trusted-for-crap") {
		t.Error("is-trusted-for-crap fails")
	}
}

func TestKeys(t *testing.T) {
	fmt.Print("\nTestKeys\n")

	keyFile := "policy_key_file.bin"
	certFile := "policy_cert_file.bin"
	fmt.Printf("Key file: %s, Cert file: %s\n", keyFile, certFile)
	serializedKey, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Println("can't read key file, ", err)
	}
	cert, err := os.ReadFile(certFile)
	if err != nil {
		fmt.Println("can't certkey file, ", err)
	}
	fmt.Printf("Key file length is %d\n", len(serializedKey))
	fmt.Printf("Cert file length is %d\n", len(cert))
	key := certprotos.KeyMessage {}
	err = proto.Unmarshal(serializedKey, &key)
	if err != nil {
		fmt.Println("can't Unmarshal key file")
	}
	fmt.Printf("Policy key name: %s\n", key.GetKeyName())
	fmt.Printf("Policy key type: %s\n", key.GetKeyType())
	PK := rsa.PublicKey{}
	pK := rsa.PrivateKey{}
	if !GetRsaKeysFromInternal(&key, &pK, &PK) {
		fmt.Printf("Can't recover keys\n")
	}

	// test rsa sign and verify
	rng := rand.Reader
	message := []byte("message to be signed")
	hashed := sha256.Sum256(message)
	fmt.Printf("Hash: ")
	PrintBytes(hashed[0:32])
	fmt.Printf("\n")
	signature, err := rsa.SignPKCS1v15(rng, &pK, crypto.SHA256, hashed[0:32])
	if err == nil {
		fmt.Printf("Signature: ")
		PrintBytes(signature)
		fmt.Printf("\n")
	}

	// verify cert
	certPool := x509.NewCertPool()
	x509cert, err := x509.ParseCertificate(cert)
	if err != nil {
		fmt.Println("Can't parse cert")
	}
	certPool.AddCert(x509cert)
	opts := x509.VerifyOptions{
		Roots:   certPool,
	}

	if _, err := x509cert.Verify(opts); err != nil {
		t.Error("failed to verify certificate")
	}
	fmt.Printf("Certificate verifies\n")

	k := MakeVseRsaKey(2048)
	var tk  string = "testkey"
	k.KeyName = &tk
	PrintKey(k)
}


func TestClaims(t *testing.T) {
	fmt.Print("\nTestClaims\n")

	policyKey := MakeVseRsaKey(2048)
	var tk  string = "policyKey"
	policyKey.KeyName = &tk
	PrintKey(policyKey)

	subj := MakeKeyEntity(policyKey)
	PrintEntity(subj)
	fmt.Printf("\n")
	m:= make([]byte, 32)
	for i := 0; i < 32; i++ {
		m[i] = byte(i)
	}
	obj:= MakeMeasurementEntity(m)
	PrintEntity(obj)
	fmt.Printf("\n")
	verbIs := "is-trusted"
	verbSays := "says"
	verbSpeaksFor:= "speaks-for"
	vcl1 := MakeUnaryVseClause(subj, &verbIs)
	PrintVseClause(vcl1)
	fmt.Printf("\n")
	vcl2 := MakeIndirectVseClause(subj, &verbSays, vcl1)
	PrintVseClause(vcl2)
	fmt.Printf("\n")
	vcl3 := MakeSimpleVseClause(subj, &verbSpeaksFor, obj)
	PrintVseClause(vcl3)
	fmt.Printf("\n")

	if !SameEntity(subj, subj) {
		t.Errorf("sameEntity fails (1)\n")
	}
	if SameEntity(subj, obj) {
		t.Errorf("sameEntity fails (2)\n")
	}
	if !SameKey(policyKey, policyKey) {
		t.Errorf("sameKey fails (1)\n")
	}
	if !SameVseClause(vcl1, vcl1) {
		t.Errorf("sameClause fails (1)\n")
	}
	if SameVseClause(vcl1, vcl2) {
		t.Errorf("sameClause fails (2)\n")
	}

	serClaim, err := proto.Marshal(vcl3)
	if err != nil {
		t.Errorf("Marshal fails\n")
	}

	tn := TimePointNow()
	tf := TimePointPlus(tn, 365 * 86400)
	nb := TimePointToString(tn)
	na := TimePointToString(tf)
	cl1 := MakeClaim(serClaim, "vse-clause", "first says", nb, na)
	PrintClaim(cl1)
	sc1 := MakeSignedClaim(cl1, policyKey)
	fmt.Printf("\nSigned claim\n")
	PrintSignedClaim(sc1)
	if !VerifySignedClaim(sc1, policyKey) {
		t.Errorf("Verify signed claim fails\n")
	}

/*
	fmt.Printf("\nAttest\n")
	vat := VseAttestation("testAttestation", "simulated-enclave", "", vcl3)
	if  vat == nil {
		t.Errorf("attestation fails")
	}
	uvat :=  certprotos.Attestation{}
	err = proto.Unmarshal(vat, &uvat)
	if err != nil {
		t.Errorf("attestation unmarshal fails")
	}
	PrintAttestation(&uvat)
*/
}

func TestCrypt(t *testing.T) {
	fmt.Println("\nTestCert")

	k := make([]byte, 32)
	iv := make([]byte, 16)
	for i := 0; i < 32; i++ {
		k[i] = byte(i)
	}
	for i := 0; i < 16; i++ {
		iv[i] = byte(i+8)
	}
	plainText := make([]byte, 62)
	for i := 0; i < 62; i++ {
		plainText[i] = byte(i+2)
	}
	cipherText := Encrypt(plainText, k, iv)
	recoveredText := Decrypt(cipherText, k)
	fmt.Printf("Plaintext size : %d\n", len(plainText))
	fmt.Printf("Cipher size out: %d\n", len(cipherText))
	fmt.Printf("Recovered size out: %d\n", len(recoveredText))
	fmt.Print("Key           : ")
	PrintBytes(k)
	fmt.Println("")
	fmt.Print("iv            : ")
	PrintBytes(iv)
	fmt.Println("")
	fmt.Print("Plain text    : ")
	PrintBytes(plainText)
	fmt.Println("")
	fmt.Print("Cipher text   : ")
	PrintBytes(cipherText)
	fmt.Println("")
	fmt.Print("Recovered text: ")
	PrintBytes(recoveredText)
	fmt.Println("")
	if !bytes.Equal(plainText, recoveredText) {
		t.Errorf("encrypt/decrypt fails")
	}

	fmt.Println()

	authenticatedPlainText := plainText
	authenticatedCipherText := AuthenticatedEncrypt(authenticatedPlainText, k, iv)
	authenticatedRecoveredText := AuthenticatedDecrypt(authenticatedCipherText, k)
	fmt.Printf("Authenticated Plaintext size : %d\n", len(authenticatedPlainText))
	fmt.Printf("Authenticated Cipher size out: %d\n", len(authenticatedCipherText))
	fmt.Printf("Authenticated Recovered size out: %d\n", len(authenticatedRecoveredText))
	fmt.Print("Key           : ")
	PrintBytes(k)
	fmt.Println("")
	fmt.Print("iv            : ")
	PrintBytes(iv)
	fmt.Println("")
	fmt.Print("Authenticated Plain text    : ")
	PrintBytes(authenticatedPlainText)
	fmt.Println("")
	fmt.Print("Authenticated Cipher text   : ")
	PrintBytes(authenticatedCipherText)
	fmt.Print("Authenticated Recovered text: ")
	PrintBytes(authenticatedRecoveredText)
	fmt.Println("")
	if !bytes.Equal(authenticatedPlainText, authenticatedRecoveredText) {
		t.Errorf("encrypt/decrypt fails")
	}
}

func TestProofsAuth(t *testing.T) {
	fmt.Print("\nTestProofsAuth\n")

	if !InitSimulatedEnclave() {
		t.Errorf("Cannot init simulated enclave")
	}

	privatePolicyKey := MakeVseRsaKey(2048)
	var tpk  string = "policyKey"
	privatePolicyKey.KeyName = &tpk
	PrintKey(privatePolicyKey)
	policyKey := InternalPublicFromPrivateKey(privatePolicyKey)
	policySubj := MakeKeyEntity(policyKey)
	fmt.Println("\nPolicy key")
	PrintEntity(policySubj)

	privateIntelKey := MakeVseRsaKey(2048)
	iek  := "intelKey"
	privateIntelKey.KeyName = &iek
	PrintKey(privateIntelKey)
	fmt.Println("")
	intelKey := InternalPublicFromPrivateKey(privateIntelKey)
	intelSubj := MakeKeyEntity(intelKey)
	fmt.Println("\nAttest key")
	PrintEntity(intelSubj)

	privateAttestKey := MakeVseRsaKey(2048)
	aek  := "attestKey"
	privateAttestKey.KeyName = &aek
	PrintKey(privateAttestKey)
	fmt.Println("")
	attestKey := InternalPublicFromPrivateKey(privateAttestKey)
	attestSubj := MakeKeyEntity(attestKey)
	fmt.Println("\nAttest key")
	PrintEntity(attestSubj)

	privateEnclaveKey := MakeVseRsaKey(2048)
	tek  := "enclaveKey"
	privateEnclaveKey.KeyName = &tek
	PrintKey(privateEnclaveKey)
	fmt.Println("")
	enclaveKey := InternalPublicFromPrivateKey(privateEnclaveKey)
	enclaveSubj := MakeKeyEntity(enclaveKey)
	fmt.Println("\nEnclave key")
	PrintEntity(enclaveSubj)

	m:= make([]byte, 32)
	for i := 0; i < 32; i++ {
		m[i] = byte(i)
	}
	entObj:= MakeMeasurementEntity(m)
	fmt.Println("\nEnclave measurement")
	PrintEntity(entObj)

	verbIs := "is-trusted"
	verbSays := "says"
	verbSpeaksFor:= "speaks-for"
	verbIsTrustedForAuth := "is-trusted-for-authentication"
	verbIsTrustedForAtt := "is-trusted-for-attestation"

	intelKeyIsTrusted := MakeUnaryVseClause(intelSubj, &verbIsTrustedForAtt)
	attestKeyIsTrusted := MakeUnaryVseClause(attestSubj, &verbIsTrustedForAtt)
	measurementIsTrusted :=  MakeUnaryVseClause(entObj, &verbIs)
	enclaveKeyIsTrusted := MakeUnaryVseClause(enclaveSubj, &verbIsTrustedForAuth)

	policyKeySaysIntelKeyIsTrusted :=  MakeIndirectVseClause(policySubj, &verbSays, intelKeyIsTrusted)
	intelKeySaysAttestKeyIsTrusted := MakeIndirectVseClause(intelSubj, &verbSays, attestKeyIsTrusted)
	policyKeySaysMeasurementIsTrusted :=  MakeIndirectVseClause(policySubj, &verbSays, measurementIsTrusted)

	enclaveKeySpeaksForMeasurement:=  MakeSimpleVseClause(enclaveSubj, &verbSpeaksFor, entObj)
	attestKeySaysEnclaveKeySpeaksForMeasurement:=  MakeIndirectVseClause(attestSubj, &verbSays, enclaveKeySpeaksForMeasurement)

	// make signed assertions
	tn := TimePointNow()
	tf := TimePointPlus(tn, 365 * 86400)
	nb := TimePointToString(tn)
	na := TimePointToString(tf)
	vfmt := "vse-clause"
	d1 := "policyKey says intelKey is-trusted-for-attestation"
	d2 := "policyKey says Measurement is-trusted"
	d3 := "intelKey says attestKey is-trusted-for-attestation"
	d4 := "attest Key says entityKey speaks-for entityMeasurement"

	serPolicyKeySaysIntelKeyIsTrusted, _:= proto.Marshal(policyKeySaysIntelKeyIsTrusted)
	clPolicyKeySaysIntelKeyIsTrusted := MakeClaim(serPolicyKeySaysIntelKeyIsTrusted, vfmt, d1, nb, na)
	signedPolicyKeySaysIntelKeyIsTrusted := MakeSignedClaim(clPolicyKeySaysIntelKeyIsTrusted, privatePolicyKey)

	serPolicyKeySaysMeasurementIsTrusted, _:= proto.Marshal(policyKeySaysMeasurementIsTrusted)
	clPolicyKeySaysMeasurementIsTrusted := MakeClaim(serPolicyKeySaysMeasurementIsTrusted, vfmt, d2, nb, na)
	signedPolicyKeySaysMeasurementIsTrusted := MakeSignedClaim(clPolicyKeySaysMeasurementIsTrusted, privatePolicyKey)

	serIntelKeySaysAttestKeyIsTrusted, _:= proto.Marshal(intelKeySaysAttestKeyIsTrusted)
	clIntelKeySaysAttestKeyIsTrusted := MakeClaim(serIntelKeySaysAttestKeyIsTrusted, vfmt, d3, nb, na)
	signedIntelKeySaysAttestKeyIsTrusted := MakeSignedClaim(clIntelKeySaysAttestKeyIsTrusted, privateIntelKey)

	serAttestKeySaysEnclaveKeySpeaksForMeasurement, _ := proto.Marshal(attestKeySaysEnclaveKeySpeaksForMeasurement)
	clAttestKeySaysEnclaveKeySpeaksForMeasurement := MakeClaim(serAttestKeySaysEnclaveKeySpeaksForMeasurement, vfmt, d4, nb, na)
	signedAttestKeySaysEnclaveKeySpeaksForMeasurement := MakeSignedClaim(clAttestKeySaysEnclaveKeySpeaksForMeasurement, privateAttestKey)

        var evidenceList []*certprotos.Evidence
	ps := certprotos.ProvedStatements{}
        scStr := "signed-claim"

        e1 := certprotos.Evidence {}
        e1.EvidenceType = &scStr
        sc1, err := proto.Marshal(signedPolicyKeySaysIntelKeyIsTrusted)
        if err != nil {
                t.Errorf("Marshal fails\n")
        }
        e1.SerializedEvidence = sc1
        evidenceList = append(evidenceList, &e1)

        e2 := certprotos.Evidence {}
        e2.EvidenceType = &scStr
        sc2, err := proto.Marshal(signedPolicyKeySaysMeasurementIsTrusted)
        if err != nil {
                t.Errorf("Marshal fails\n")
        }
        e2.SerializedEvidence = sc2
        evidenceList = append(evidenceList, &e2)

        e3 := certprotos.Evidence {}
        e3.EvidenceType = &scStr
        sc3, err := proto.Marshal(signedIntelKeySaysAttestKeyIsTrusted)
        if err != nil {
                t.Errorf("Marshal fails\n")
        }
        e3.SerializedEvidence = sc3
        evidenceList = append(evidenceList, &e3)

        e4 := certprotos.Evidence {}
        e4.EvidenceType = &scStr
        sc4, err := proto.Marshal(signedAttestKeySaysEnclaveKeySpeaksForMeasurement)
        if err != nil {
                t.Errorf("Marshal fails\n")
        }
        e4.SerializedEvidence = sc4
        evidenceList = append(evidenceList, &e4)


	fmt.Println("Public policy key")
	PrintKey(policyKey)
	fmt.Println("")

	if !InitProvedStatements(*policyKey, evidenceList, &ps) {
		t.Errorf("Cannot init proved statements")
	}
	fmt.Printf("Initial proved statements %d\n", len(ps.Proved))
	for i := 0; i < len(ps.Proved); i++ {
		PrintVseClause(ps.Proved[i])
		fmt.Println("")
	}
	fmt.Println("")

	// The proof
	p := certprotos.Proof{}

	r1 := int32(1)
	r3 := int32(3)
	r5 := int32(5)
	r6 := int32(6)
	ps1 := certprotos.ProofStep {
		S1: ps.Proved[0],
		S2: policyKeySaysMeasurementIsTrusted,
		Conclusion: measurementIsTrusted,
		RuleApplied: &r3,
	}
	p.Steps = append(p.Steps, &ps1)
	ps2 := certprotos.ProofStep {
		S1: ps.Proved[0],
		S2: policyKeySaysIntelKeyIsTrusted,
		Conclusion: intelKeyIsTrusted,
		RuleApplied: &r5,
	}
	p.Steps = append(p.Steps, &ps2)
	ps3 := certprotos.ProofStep {
		S1: intelKeyIsTrusted,
		S2: intelKeySaysAttestKeyIsTrusted,
		Conclusion: attestKeyIsTrusted,
		RuleApplied: &r5,
	}
	p.Steps = append(p.Steps, &ps3)
	ps4 := certprotos.ProofStep {
		S1: attestKeyIsTrusted,
		S2: attestKeySaysEnclaveKeySpeaksForMeasurement,
		Conclusion: enclaveKeySpeaksForMeasurement,
		RuleApplied: &r6,
	}
	p.Steps = append(p.Steps, &ps4)
	ps5 := certprotos.ProofStep {
		S1: measurementIsTrusted,
		S2: enclaveKeySpeaksForMeasurement,
		Conclusion: enclaveKeyIsTrusted,
		RuleApplied: &r1,
	}
	p.Steps = append(p.Steps, &ps5)


	if VerifyProof(policyKey, enclaveKeyIsTrusted, &p, &ps) {
		fmt.Printf("Proved: ")
		PrintVseClause(enclaveKeyIsTrusted)
		fmt.Println("")
	} else {
		fmt.Printf("Not proved: ")
		PrintVseClause(enclaveKeyIsTrusted)
		fmt.Println("")
		t.Errorf("Cannot prove statement")
	}
	fmt.Printf("\n\nFinal proved statements %d\n", len(ps.Proved))
	for i := 0; i < len(ps.Proved); i++ {
		PrintVseClause(ps.Proved[i])
		fmt.Println("")
	}
}

func TestProofsAttest(t *testing.T) {
	fmt.Print("\nTestProofsAttest\n")

	if !InitSimulatedEnclave() {
		t.Errorf("Cannot init simulated enclave")
	}

	privatePolicyKey := MakeVseRsaKey(2048)
	var tpk  string = "policyKey"
	privatePolicyKey.KeyName = &tpk
	PrintKey(privatePolicyKey)
	policyKey := InternalPublicFromPrivateKey(privatePolicyKey)
	policySubj := MakeKeyEntity(policyKey)
	fmt.Println("\nPolicy key")
	PrintEntity(policySubj)

	privateIntelKey := MakeVseRsaKey(2048)
	iek  := "intelKey"
	privateIntelKey.KeyName = &iek
	PrintKey(privateIntelKey)
	fmt.Println("")
	intelKey := InternalPublicFromPrivateKey(privateIntelKey)
	intelSubj := MakeKeyEntity(intelKey)
	fmt.Println("\nAttest key")
	PrintEntity(intelSubj)

	privateAttestKey := MakeVseRsaKey(2048)
	aek  := "attestKey"
	privateAttestKey.KeyName = &aek
	PrintKey(privateAttestKey)
	fmt.Println("")
	attestKey := InternalPublicFromPrivateKey(privateAttestKey)
	attestSubj := MakeKeyEntity(attestKey)
	fmt.Println("\nAttest key")
	PrintEntity(attestSubj)

	privateEnclaveKey := MakeVseRsaKey(2048)
	tek  := "enclaveKey"
	privateEnclaveKey.KeyName = &tek
	PrintKey(privateEnclaveKey)
	fmt.Println("")
	enclaveKey := InternalPublicFromPrivateKey(privateEnclaveKey)
	enclaveSubj := MakeKeyEntity(enclaveKey)
	fmt.Println("\nEnclave key")
	PrintEntity(enclaveSubj)

	m:= make([]byte, 32)
	for i := 0; i < 32; i++ {
		m[i] = byte(i)
	}
	entObj:= MakeMeasurementEntity(m)
	fmt.Println("\nEnclave measurement")
	PrintEntity(entObj)

	verbIs := "is-trusted"
	verbSays := "says"
	verbSpeaksFor:= "speaks-for"
	verbIsTrustedForAtt := "is-trusted-for-attestation"

	intelKeyIsTrusted := MakeUnaryVseClause(intelSubj, &verbIsTrustedForAtt)
	attestKeyIsTrusted := MakeUnaryVseClause(attestSubj, &verbIsTrustedForAtt)
	measurementIsTrusted :=  MakeUnaryVseClause(entObj, &verbIs)
	enclaveKeyIsTrusted := MakeUnaryVseClause(enclaveSubj, &verbIsTrustedForAtt)

	policyKeySaysIntelKeyIsTrusted :=  MakeIndirectVseClause(policySubj, &verbSays, intelKeyIsTrusted)
	intelKeySaysAttestKeyIsTrusted := MakeIndirectVseClause(intelSubj, &verbSays, attestKeyIsTrusted)
	policyKeySaysMeasurementIsTrusted :=  MakeIndirectVseClause(policySubj, &verbSays, measurementIsTrusted)

	enclaveKeySpeaksForMeasurement:=  MakeSimpleVseClause(enclaveSubj, &verbSpeaksFor, entObj)
	attestKeySaysEnclaveKeySpeaksForMeasurement:=  MakeIndirectVseClause(attestSubj, &verbSays, enclaveKeySpeaksForMeasurement)

	// make signed assertions
	tn := TimePointNow()
	tf := TimePointPlus(tn, 365 * 86400)
	nb := TimePointToString(tn)
	na := TimePointToString(tf)
	vfmt := "vse-clause"
	d1 := "policyKey says intelKey is-trusted-for-attestation"
	d2 := "policyKey says Measurement is-trusted"
	d3 := "intelKey says attestKey is-trusted-for-attestation"
	d4 := "attest Key says entityKey speaks-for entityMeasurement"

	serPolicyKeySaysIntelKeyIsTrusted, _:= proto.Marshal(policyKeySaysIntelKeyIsTrusted)
	clPolicyKeySaysIntelKeyIsTrusted := MakeClaim(serPolicyKeySaysIntelKeyIsTrusted, vfmt, d1, nb, na)
	signedPolicyKeySaysIntelKeyIsTrusted := MakeSignedClaim(clPolicyKeySaysIntelKeyIsTrusted, privatePolicyKey)

	serPolicyKeySaysMeasurementIsTrusted, _:= proto.Marshal(policyKeySaysMeasurementIsTrusted)
	clPolicyKeySaysMeasurementIsTrusted := MakeClaim(serPolicyKeySaysMeasurementIsTrusted, vfmt, d2, nb, na)
	signedPolicyKeySaysMeasurementIsTrusted := MakeSignedClaim(clPolicyKeySaysMeasurementIsTrusted, privatePolicyKey)

	serIntelKeySaysAttestKeyIsTrusted, _:= proto.Marshal(intelKeySaysAttestKeyIsTrusted)
	clIntelKeySaysAttestKeyIsTrusted := MakeClaim(serIntelKeySaysAttestKeyIsTrusted, vfmt, d3, nb, na)
	signedIntelKeySaysAttestKeyIsTrusted := MakeSignedClaim(clIntelKeySaysAttestKeyIsTrusted, privateIntelKey)

	serAttestKeySaysEnclaveKeySpeaksForMeasurement, _ := proto.Marshal(attestKeySaysEnclaveKeySpeaksForMeasurement)
	clAttestKeySaysEnclaveKeySpeaksForMeasurement := MakeClaim(serAttestKeySaysEnclaveKeySpeaksForMeasurement, vfmt, d4, nb, na)
	signedAttestKeySaysEnclaveKeySpeaksForMeasurement := MakeSignedClaim(clAttestKeySaysEnclaveKeySpeaksForMeasurement, privateAttestKey)

        var evidenceList []*certprotos.Evidence
	ps := certprotos.ProvedStatements{}
        scStr := "signed-claim"

        e1 := certprotos.Evidence {}
        e1.EvidenceType = &scStr
        sc1, err := proto.Marshal(signedPolicyKeySaysIntelKeyIsTrusted)
        if err != nil {
                t.Errorf("Marshal fails\n")
        }
        e1.SerializedEvidence = sc1
        evidenceList = append(evidenceList, &e1)

        e2 := certprotos.Evidence {}
        e2.EvidenceType = &scStr
        sc2, err := proto.Marshal(signedPolicyKeySaysMeasurementIsTrusted)
        if err != nil {
                t.Errorf("Marshal fails\n")
        }
        e2.SerializedEvidence = sc2
        evidenceList = append(evidenceList, &e2)

        e3 := certprotos.Evidence {}
        e3.EvidenceType = &scStr
        sc3, err := proto.Marshal(signedIntelKeySaysAttestKeyIsTrusted)
        if err != nil {
                t.Errorf("Marshal fails\n")
        }
        e3.SerializedEvidence = sc3
        evidenceList = append(evidenceList, &e3)

        e4 := certprotos.Evidence {}
        e4.EvidenceType = &scStr
        sc4, err := proto.Marshal(signedAttestKeySaysEnclaveKeySpeaksForMeasurement)
        if err != nil {
                t.Errorf("Marshal fails\n")
        }
        e4.SerializedEvidence = sc4
        evidenceList = append(evidenceList, &e4)


	fmt.Println("Public policy key")
	PrintKey(policyKey)
	fmt.Println("")

	if !InitProvedStatements(*policyKey, evidenceList, &ps) {
		t.Errorf("Cannot init proved statements")
	}
	fmt.Printf("Initial proved statements %d\n", len(ps.Proved))
	for i := 0; i < len(ps.Proved); i++ {
		PrintVseClause(ps.Proved[i])
		fmt.Println("")
	}
	fmt.Println("")

	// The proof
	p := certprotos.Proof{}

	r3 := int32(3)
	r5 := int32(5)
	r6 := int32(6)
	r7 := int32(7)
	ps1 := certprotos.ProofStep {
		S1: ps.Proved[0],
		S2: policyKeySaysMeasurementIsTrusted,
		Conclusion: measurementIsTrusted,
		RuleApplied: &r3,
	}
	p.Steps = append(p.Steps, &ps1)
	ps2 := certprotos.ProofStep {
		S1: ps.Proved[0],
		S2: policyKeySaysIntelKeyIsTrusted,
		Conclusion: intelKeyIsTrusted,
		RuleApplied: &r5,
	}
	p.Steps = append(p.Steps, &ps2)
	ps3 := certprotos.ProofStep {
		S1: intelKeyIsTrusted,
		S2: intelKeySaysAttestKeyIsTrusted,
		Conclusion: attestKeyIsTrusted,
		RuleApplied: &r5,
	}
	p.Steps = append(p.Steps, &ps3)
	ps4 := certprotos.ProofStep {
		S1: attestKeyIsTrusted,
		S2: attestKeySaysEnclaveKeySpeaksForMeasurement,
		Conclusion: enclaveKeySpeaksForMeasurement,
		RuleApplied: &r6,
	}
	p.Steps = append(p.Steps, &ps4)
	ps5 := certprotos.ProofStep {
		S1: measurementIsTrusted,
		S2: enclaveKeySpeaksForMeasurement,
		Conclusion: enclaveKeyIsTrusted,
		RuleApplied: &r7,
	}
	p.Steps = append(p.Steps, &ps5)


	if VerifyProof(policyKey, enclaveKeyIsTrusted, &p, &ps) {
		fmt.Printf("Proved: ")
		PrintVseClause(enclaveKeyIsTrusted)
		fmt.Println("")
	} else {
		fmt.Printf("Not proved: ")
		PrintVseClause(enclaveKeyIsTrusted)
		fmt.Println("")
		t.Errorf("Cannot prove statement")
	}
	fmt.Printf("\n\nFinal proved statements %d\n", len(ps.Proved))
	for i := 0; i < len(ps.Proved); i++ {
		PrintVseClause(ps.Proved[i])
		fmt.Println("")
	}
}

func TestArtifacts(t *testing.T) {
	fmt.Print("\nTestArtifacts\n")

        privateIssuerKey := MakeVseRsaKey(2048)
        var ipk  string = "issuerKey"
        privateIssuerKey.KeyName = &ipk
        PrintKey(privateIssuerKey)
        // issuerKey := InternalPublicFromPrivateKey(privateIssuerKey)
        fmt.Println("\nIssuer key")
        PrintKey(privateIssuerKey)

        privateSubjKey := MakeVseRsaKey(2048)
        var spk  string = "subjKey"
        privateSubjKey.KeyName = &spk
        PrintKey(privateSubjKey)
        subjKey := InternalPublicFromPrivateKey(privateSubjKey)
        fmt.Println("\nSubj key")
        PrintKey(privateSubjKey)

	sn := big.Int{}
	sn.SetInt64(int64(1))
	parentCert := x509.Certificate{
                SerialNumber: &sn,
                Subject: pkix.Name{
                        CommonName:   "testIssuer",
                },
                NotBefore:             time.Now(),
                NotAfter:              time.Now().Add(365*86400*1000000000),
                KeyUsage:              x509.KeyUsageCertSign,
                ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
                BasicConstraintsValid: true,
                IsCA: true,
        }
	ipK := rsa.PrivateKey{}
	iPK := rsa.PublicKey{}
	if !GetRsaKeysFromInternal(privateIssuerKey, &ipK, &iPK) {
                t.Error("Can't Create parent Key")
	}

	parentDerCert, err := x509.CreateCertificate(rand.Reader, &parentCert, &parentCert,
                &ipK.PublicKey, crypto.Signer(&ipK))
        if err != nil {
                t.Error("Can't Create parent Certificate")
        }
	newParentCert, err := x509.ParseCertificate(parentDerCert)
        if err != nil {
                t.Error("Can't parse parent Certificate")
        }

	cert := ProduceAdmissionCert(privateIssuerKey, newParentCert, subjKey, "testSubject", "",
                uint64(5), 365.0 * 86400)
	fmt.Println("")
	if cert == nil {
		fmt.Println("ProduceArtifact returned nil")
	}
	issuerName := GetIssuerNameFromCert(cert)
	if issuerName != nil {
		fmt.Printf("Issuer Name: %s\n",  *issuerName)
	}
		subjName := GetSubjectNameFromCert(cert)
	if subjName != nil {
		fmt.Printf("Subject Name: %s\n",  *subjName)
	}
	sk := GetSubjectKey(cert)
	if sk != nil {
		PrintKey(sk)
	}
	if !VerifyAdmissionCert(newParentCert, cert) {
                t.Error("Artifact does not verify")
	}
}

type MyInterface interface {
	Func1(i int) int
	Func2(i int) string
}

type MyInt int

func (r *MyInt) Func1(in int) int {
	return in + 1
}

func (r *MyInt) Func2(in int) string{
	return  fmt.Sprintf("***%d", in)
}

type MyCryptoSigner rsa.PrivateKey

func (r *MyCryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return nil, nil
}

func TestInterface(t *testing.T) {
	fmt.Print("\nTestInterface\n")

	var i MyInt = 3
	fmt.Println(i.Func1(3))
	fmt.Println(i.Func2(3))
}

