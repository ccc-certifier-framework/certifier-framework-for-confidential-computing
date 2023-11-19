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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	//"net"
	"os"
	//"syscall"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	certprotos "github.com/vmware-research/certifier-framework-for-confidential-computing/certifier_service/certprotos"
)

/*
func TestTEEAttest(t *testing.T) {
	fmt.Print("\nTestTEEAttest\n")

	var what_to_say []byte
	what_to_say = make([]byte, 256)
	for i := 0; i < 256; i++ {
		what_to_say[i] = byte(i)
	}
	evidence, err := TEEAttest("sev-enclave", what_to_say)
	if err != nil {
		fmt.Printf("TEEAttest failed: %s\n", err.Error())
		t.Errorf("TestTEEAttest failed")
	}
	fmt.Printf("evidence length: %d\n", len(evidence))
}

func TestTEESeal(t *testing.T) {
	fmt.Print("\nTestTEESeal\n")

	var in []byte
	in = make([]byte, 32)
	for i := 0; i < 32; i++ {
		in[i] = byte((7 * i) % 16)
	}
	cipher, err := TEESeal("sev-enclave", "test-enclave", in, 256)
	if err != nil {
		fmt.Printf("TEESeal failed: %s\n", err.Error())
		t.Errorf("TestTEESeal failed")
	}
	fmt.Printf("Cipher text length: %d\n", len(cipher))

	clear, err := TEEUnSeal("sev-enclave", "test-enclave", cipher, 128)
	if err != nil {
		fmt.Printf("TEEUnseal failed: %s\n", err.Error())
		t.Errorf("TestTEESeal failed")
	}
	fmt.Printf("Clear text length: %d\n", len(clear))
	if !bytes.Equal(in, clear) {
		fmt.Printf("Clear text mismatch\n")
		t.Errorf("TestTEESeal failed")
	}
}
*/

func TestEntity(t *testing.T) {
	fmt.Print("\nTestEntity\n")
	m := make([]byte, 32)
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
	tf := TimePointPlus(tn, 365*86400)
	PrintTimePoint(tf)
	fmt.Printf("\n")
	if CompareTimePoints(tn, tf) != (-1) {
		t.Errorf("Comparetime fails")
	}
	st := TimePointToString(tf)
	tf2 := StringToTimePoint(st)
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

	root := PredicateDominance{
		Predicate:  "is-trusted",
		FirstChild: nil,
		Next:       nil,
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

	keyFile := "./test_data/policy_key_file.bin"
	certFile := "./test_data/policy_cert_file.bin"
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
	key := certprotos.KeyMessage{}
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
		Roots: certPool,
	}

	if _, err := x509cert.Verify(opts); err != nil {
		t.Error("failed to verify certificate")
	}
	fmt.Printf("Certificate verifies\n")

	k := MakeVseRsaKey(2048)
	var tk string = "testkey"
	k.KeyName = &tk
	PrintKey(k)
}

func TestClaims(t *testing.T) {
	fmt.Print("\nTestClaims\n")

	policyKey := MakeVseRsaKey(2048)
	var tk string = "policyKey"
	policyKey.KeyName = &tk
	PrintKey(policyKey)

	subj := MakeKeyEntity(policyKey)
	PrintEntity(subj)
	fmt.Printf("\n")
	m := make([]byte, 32)
	for i := 0; i < 32; i++ {
		m[i] = byte(i)
	}
	obj := MakeMeasurementEntity(m)
	PrintEntity(obj)
	fmt.Printf("\n")
	verbIs := "is-trusted"
	verbSays := "says"
	verbSpeaksFor := "speaks-for"
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
	tf := TimePointPlus(tn, 365*86400)
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
		// Just prints attestation, not really needed in test
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
		iv[i] = byte(i + 8)
	}
	plainText := make([]byte, 62)
	for i := 0; i < 62; i++ {
		plainText[i] = byte(i + 2)
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
	authenticatedCipherText := GeneralAuthenticatedEncrypt("aes-256-cbc-hmac-sha256", authenticatedPlainText, k, iv)
	authenticatedRecoveredText := GeneralAuthenticatedDecrypt("aes-256-cbc-hmac-sha256", authenticatedCipherText, k)
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

	// GCM authenticated encrypt
	authenticatedPlainText2 := plainText
	authenticatedCipherText2 := GeneralAuthenticatedEncrypt("aes-256-gcm", authenticatedPlainText2, k, iv)
	authenticatedRecoveredText2 := GeneralAuthenticatedDecrypt("aes-256-gcm", authenticatedCipherText2, k)
	fmt.Printf("Authenticated Plaintext size : %d\n", len(authenticatedPlainText2))
	fmt.Printf("Authenticated Cipher size out: %d\n", len(authenticatedCipherText2))
	fmt.Printf("Authenticated Recovered size out: %d\n", len(authenticatedRecoveredText2))
	fmt.Print("Key           : ")
	PrintBytes(k)
	fmt.Println("")
	fmt.Print("iv            : ")
	PrintBytes(iv)
	fmt.Println("")
	fmt.Print("Authenticated Plain text    : ")
	PrintBytes(authenticatedPlainText2)
	fmt.Println("")
	fmt.Print("Authenticated Cipher text   : ")
	PrintBytes(authenticatedCipherText2)
	fmt.Print("Authenticated Recovered text: ")
	PrintBytes(authenticatedRecoveredText2)
	fmt.Println("")
	if !bytes.Equal(authenticatedPlainText2, authenticatedRecoveredText2) {
		t.Errorf("encrypt/decrypt fails")
	}

}

func TestProofsAuth(t *testing.T) {
	fmt.Print("\nTestProofsAuth\n")

	if !InitSimulatedEnclave() {
		t.Errorf("Cannot init simulated enclave")
	}

	privatePolicyKey := MakeVseRsaKey(2048)
	var tpk string = "policyKey"
	privatePolicyKey.KeyName = &tpk
	PrintKey(privatePolicyKey)
	policyKey := InternalPublicFromPrivateKey(privatePolicyKey)
	policySubj := MakeKeyEntity(policyKey)
	fmt.Println("\nPolicy key")
	PrintEntity(policySubj)

	privateIntelKey := MakeVseRsaKey(2048)
	iek := "intelKey"
	privateIntelKey.KeyName = &iek
	PrintKey(privateIntelKey)
	fmt.Println("")
	intelKey := InternalPublicFromPrivateKey(privateIntelKey)
	intelSubj := MakeKeyEntity(intelKey)
	fmt.Println("\nAttest key")
	PrintEntity(intelSubj)

	privateAttestKey := MakeVseRsaKey(2048)
	aek := "attestKey"
	privateAttestKey.KeyName = &aek
	PrintKey(privateAttestKey)
	fmt.Println("")
	attestKey := InternalPublicFromPrivateKey(privateAttestKey)
	attestSubj := MakeKeyEntity(attestKey)
	fmt.Println("\nAttest key")
	PrintEntity(attestSubj)

	privateEnclaveKey := MakeVseRsaKey(2048)
	tek := "enclaveKey"
	privateEnclaveKey.KeyName = &tek
	PrintKey(privateEnclaveKey)
	fmt.Println("")
	enclaveKey := InternalPublicFromPrivateKey(privateEnclaveKey)
	enclaveSubj := MakeKeyEntity(enclaveKey)
	fmt.Println("\nEnclave key")
	PrintEntity(enclaveSubj)

	m := make([]byte, 32)
	for i := 0; i < 32; i++ {
		m[i] = byte(i)
	}
	entObj := MakeMeasurementEntity(m)
	fmt.Println("\nEnclave measurement")
	PrintEntity(entObj)

	verbIs := "is-trusted"
	verbSays := "says"
	verbSpeaksFor := "speaks-for"
	verbIsTrustedForAuth := "is-trusted-for-authentication"
	verbIsTrustedForAtt := "is-trusted-for-attestation"

	intelKeyIsTrusted := MakeUnaryVseClause(intelSubj, &verbIsTrustedForAtt)
	attestKeyIsTrusted := MakeUnaryVseClause(attestSubj, &verbIsTrustedForAtt)
	measurementIsTrusted := MakeUnaryVseClause(entObj, &verbIs)
	enclaveKeyIsTrusted := MakeUnaryVseClause(enclaveSubj, &verbIsTrustedForAuth)

	policyKeySaysIntelKeyIsTrusted := MakeIndirectVseClause(policySubj, &verbSays, intelKeyIsTrusted)
	intelKeySaysAttestKeyIsTrusted := MakeIndirectVseClause(intelSubj, &verbSays, attestKeyIsTrusted)
	policyKeySaysMeasurementIsTrusted := MakeIndirectVseClause(policySubj, &verbSays, measurementIsTrusted)

	enclaveKeySpeaksForMeasurement := MakeSimpleVseClause(enclaveSubj, &verbSpeaksFor, entObj)
	attestKeySaysEnclaveKeySpeaksForMeasurement := MakeIndirectVseClause(attestSubj, &verbSays, enclaveKeySpeaksForMeasurement)

	// make signed assertions
	tn := TimePointNow()
	tf := TimePointPlus(tn, 365*86400)
	nb := TimePointToString(tn)
	na := TimePointToString(tf)
	vfmt := "vse-clause"
	d1 := "policyKey says intelKey is-trusted-for-attestation"
	d2 := "policyKey says Measurement is-trusted"
	d3 := "intelKey says attestKey is-trusted-for-attestation"
	d4 := "attest Key says entityKey speaks-for entityMeasurement"

	serPolicyKeySaysIntelKeyIsTrusted, _ := proto.Marshal(policyKeySaysIntelKeyIsTrusted)
	clPolicyKeySaysIntelKeyIsTrusted := MakeClaim(serPolicyKeySaysIntelKeyIsTrusted, vfmt, d1, nb, na)
	signedPolicyKeySaysIntelKeyIsTrusted := MakeSignedClaim(clPolicyKeySaysIntelKeyIsTrusted, privatePolicyKey)

	serPolicyKeySaysMeasurementIsTrusted, _ := proto.Marshal(policyKeySaysMeasurementIsTrusted)
	clPolicyKeySaysMeasurementIsTrusted := MakeClaim(serPolicyKeySaysMeasurementIsTrusted, vfmt, d2, nb, na)
	signedPolicyKeySaysMeasurementIsTrusted := MakeSignedClaim(clPolicyKeySaysMeasurementIsTrusted, privatePolicyKey)

	serIntelKeySaysAttestKeyIsTrusted, _ := proto.Marshal(intelKeySaysAttestKeyIsTrusted)
	clIntelKeySaysAttestKeyIsTrusted := MakeClaim(serIntelKeySaysAttestKeyIsTrusted, vfmt, d3, nb, na)
	signedIntelKeySaysAttestKeyIsTrusted := MakeSignedClaim(clIntelKeySaysAttestKeyIsTrusted, privateIntelKey)

	serAttestKeySaysEnclaveKeySpeaksForMeasurement, _ := proto.Marshal(attestKeySaysEnclaveKeySpeaksForMeasurement)
	clAttestKeySaysEnclaveKeySpeaksForMeasurement := MakeClaim(serAttestKeySaysEnclaveKeySpeaksForMeasurement, vfmt, d4, nb, na)
	signedAttestKeySaysEnclaveKeySpeaksForMeasurement := MakeSignedClaim(clAttestKeySaysEnclaveKeySpeaksForMeasurement, privateAttestKey)

	var evidenceList []*certprotos.Evidence
	ps := certprotos.ProvedStatements{}
	scStr := "signed-claim"

	e1 := certprotos.Evidence{}
	e1.EvidenceType = &scStr
	sc1, err := proto.Marshal(signedPolicyKeySaysIntelKeyIsTrusted)
	if err != nil {
		t.Errorf("Marshal fails\n")
	}
	e1.SerializedEvidence = sc1
	evidenceList = append(evidenceList, &e1)

	e2 := certprotos.Evidence{}
	e2.EvidenceType = &scStr
	sc2, err := proto.Marshal(signedPolicyKeySaysMeasurementIsTrusted)
	if err != nil {
		t.Errorf("Marshal fails\n")
	}
	e2.SerializedEvidence = sc2
	evidenceList = append(evidenceList, &e2)

	e3 := certprotos.Evidence{}
	e3.EvidenceType = &scStr
	sc3, err := proto.Marshal(signedIntelKeySaysAttestKeyIsTrusted)
	if err != nil {
		t.Errorf("Marshal fails\n")
	}
	e3.SerializedEvidence = sc3
	evidenceList = append(evidenceList, &e3)

	e4 := certprotos.Evidence{}
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

	// Next statement is here because we removed InitAxiom from InitProvedStatements
	InitAxiom(*policyKey, &ps)
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
	ps1 := certprotos.ProofStep{
		S1:          ps.Proved[0],
		S2:          policyKeySaysMeasurementIsTrusted,
		Conclusion:  measurementIsTrusted,
		RuleApplied: &r3,
	}
	p.Steps = append(p.Steps, &ps1)
	ps2 := certprotos.ProofStep{
		S1:          ps.Proved[0],
		S2:          policyKeySaysIntelKeyIsTrusted,
		Conclusion:  intelKeyIsTrusted,
		RuleApplied: &r5,
	}
	p.Steps = append(p.Steps, &ps2)
	ps3 := certprotos.ProofStep{
		S1:          intelKeyIsTrusted,
		S2:          intelKeySaysAttestKeyIsTrusted,
		Conclusion:  attestKeyIsTrusted,
		RuleApplied: &r5,
	}
	p.Steps = append(p.Steps, &ps3)
	ps4 := certprotos.ProofStep{
		S1:          attestKeyIsTrusted,
		S2:          attestKeySaysEnclaveKeySpeaksForMeasurement,
		Conclusion:  enclaveKeySpeaksForMeasurement,
		RuleApplied: &r6,
	}
	p.Steps = append(p.Steps, &ps4)
	ps5 := certprotos.ProofStep{
		S1:          measurementIsTrusted,
		S2:          enclaveKeySpeaksForMeasurement,
		Conclusion:  enclaveKeyIsTrusted,
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
	var tpk string = "policyKey"
	privatePolicyKey.KeyName = &tpk
	PrintKey(privatePolicyKey)
	policyKey := InternalPublicFromPrivateKey(privatePolicyKey)
	policySubj := MakeKeyEntity(policyKey)
	fmt.Println("\nPolicy key")
	PrintEntity(policySubj)

	privateIntelKey := MakeVseRsaKey(2048)
	iek := "intelKey"
	privateIntelKey.KeyName = &iek
	PrintKey(privateIntelKey)
	fmt.Println("")
	intelKey := InternalPublicFromPrivateKey(privateIntelKey)
	intelSubj := MakeKeyEntity(intelKey)
	fmt.Println("\nAttest key")
	PrintEntity(intelSubj)

	privateAttestKey := MakeVseRsaKey(2048)
	aek := "attestKey"
	privateAttestKey.KeyName = &aek
	PrintKey(privateAttestKey)
	fmt.Println("")
	attestKey := InternalPublicFromPrivateKey(privateAttestKey)
	attestSubj := MakeKeyEntity(attestKey)
	fmt.Println("\nAttest key")
	PrintEntity(attestSubj)

	privateEnclaveKey := MakeVseRsaKey(2048)
	tek := "enclaveKey"
	privateEnclaveKey.KeyName = &tek
	PrintKey(privateEnclaveKey)
	fmt.Println("")
	enclaveKey := InternalPublicFromPrivateKey(privateEnclaveKey)
	enclaveSubj := MakeKeyEntity(enclaveKey)
	fmt.Println("\nEnclave key")
	PrintEntity(enclaveSubj)

	m := make([]byte, 32)
	for i := 0; i < 32; i++ {
		m[i] = byte(i)
	}
	entObj := MakeMeasurementEntity(m)
	fmt.Println("\nEnclave measurement")
	PrintEntity(entObj)

	verbIs := "is-trusted"
	verbSays := "says"
	verbSpeaksFor := "speaks-for"
	verbIsTrustedForAtt := "is-trusted-for-attestation"

	intelKeyIsTrusted := MakeUnaryVseClause(intelSubj, &verbIsTrustedForAtt)
	attestKeyIsTrusted := MakeUnaryVseClause(attestSubj, &verbIsTrustedForAtt)
	measurementIsTrusted := MakeUnaryVseClause(entObj, &verbIs)
	enclaveKeyIsTrusted := MakeUnaryVseClause(enclaveSubj, &verbIsTrustedForAtt)

	policyKeySaysIntelKeyIsTrusted := MakeIndirectVseClause(policySubj, &verbSays, intelKeyIsTrusted)
	intelKeySaysAttestKeyIsTrusted := MakeIndirectVseClause(intelSubj, &verbSays, attestKeyIsTrusted)
	policyKeySaysMeasurementIsTrusted := MakeIndirectVseClause(policySubj, &verbSays, measurementIsTrusted)

	enclaveKeySpeaksForMeasurement := MakeSimpleVseClause(enclaveSubj, &verbSpeaksFor, entObj)
	attestKeySaysEnclaveKeySpeaksForMeasurement := MakeIndirectVseClause(attestSubj, &verbSays, enclaveKeySpeaksForMeasurement)

	// make signed assertions
	tn := TimePointNow()
	tf := TimePointPlus(tn, 365*86400)
	nb := TimePointToString(tn)
	na := TimePointToString(tf)
	vfmt := "vse-clause"
	d1 := "policyKey says intelKey is-trusted-for-attestation"
	d2 := "policyKey says Measurement is-trusted"
	d3 := "intelKey says attestKey is-trusted-for-attestation"
	d4 := "attest Key says entityKey speaks-for entityMeasurement"

	serPolicyKeySaysIntelKeyIsTrusted, _ := proto.Marshal(policyKeySaysIntelKeyIsTrusted)
	clPolicyKeySaysIntelKeyIsTrusted := MakeClaim(serPolicyKeySaysIntelKeyIsTrusted, vfmt, d1, nb, na)
	signedPolicyKeySaysIntelKeyIsTrusted := MakeSignedClaim(clPolicyKeySaysIntelKeyIsTrusted, privatePolicyKey)

	serPolicyKeySaysMeasurementIsTrusted, _ := proto.Marshal(policyKeySaysMeasurementIsTrusted)
	clPolicyKeySaysMeasurementIsTrusted := MakeClaim(serPolicyKeySaysMeasurementIsTrusted, vfmt, d2, nb, na)
	signedPolicyKeySaysMeasurementIsTrusted := MakeSignedClaim(clPolicyKeySaysMeasurementIsTrusted, privatePolicyKey)

	serIntelKeySaysAttestKeyIsTrusted, _ := proto.Marshal(intelKeySaysAttestKeyIsTrusted)
	clIntelKeySaysAttestKeyIsTrusted := MakeClaim(serIntelKeySaysAttestKeyIsTrusted, vfmt, d3, nb, na)
	signedIntelKeySaysAttestKeyIsTrusted := MakeSignedClaim(clIntelKeySaysAttestKeyIsTrusted, privateIntelKey)

	serAttestKeySaysEnclaveKeySpeaksForMeasurement, _ := proto.Marshal(attestKeySaysEnclaveKeySpeaksForMeasurement)
	clAttestKeySaysEnclaveKeySpeaksForMeasurement := MakeClaim(serAttestKeySaysEnclaveKeySpeaksForMeasurement, vfmt, d4, nb, na)
	signedAttestKeySaysEnclaveKeySpeaksForMeasurement := MakeSignedClaim(clAttestKeySaysEnclaveKeySpeaksForMeasurement, privateAttestKey)

	var evidenceList []*certprotos.Evidence
	ps := certprotos.ProvedStatements{}
	scStr := "signed-claim"

	e1 := certprotos.Evidence{}
	e1.EvidenceType = &scStr
	sc1, err := proto.Marshal(signedPolicyKeySaysIntelKeyIsTrusted)
	if err != nil {
		t.Errorf("Marshal fails\n")
	}
	e1.SerializedEvidence = sc1
	evidenceList = append(evidenceList, &e1)

	e2 := certprotos.Evidence{}
	e2.EvidenceType = &scStr
	sc2, err := proto.Marshal(signedPolicyKeySaysMeasurementIsTrusted)
	if err != nil {
		t.Errorf("Marshal fails\n")
	}
	e2.SerializedEvidence = sc2
	evidenceList = append(evidenceList, &e2)

	e3 := certprotos.Evidence{}
	e3.EvidenceType = &scStr
	sc3, err := proto.Marshal(signedIntelKeySaysAttestKeyIsTrusted)
	if err != nil {
		t.Errorf("Marshal fails\n")
	}
	e3.SerializedEvidence = sc3
	evidenceList = append(evidenceList, &e3)

	e4 := certprotos.Evidence{}
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

	// Next statement is here because we removed InitAxiom from InitProvedStatements
	InitAxiom(*policyKey, &ps)
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
	ps1 := certprotos.ProofStep{
		S1:          ps.Proved[0],
		S2:          policyKeySaysMeasurementIsTrusted,
		Conclusion:  measurementIsTrusted,
		RuleApplied: &r3,
	}
	p.Steps = append(p.Steps, &ps1)
	ps2 := certprotos.ProofStep{
		S1:          ps.Proved[0],
		S2:          policyKeySaysIntelKeyIsTrusted,
		Conclusion:  intelKeyIsTrusted,
		RuleApplied: &r5,
	}
	p.Steps = append(p.Steps, &ps2)
	ps3 := certprotos.ProofStep{
		S1:          intelKeyIsTrusted,
		S2:          intelKeySaysAttestKeyIsTrusted,
		Conclusion:  attestKeyIsTrusted,
		RuleApplied: &r5,
	}
	p.Steps = append(p.Steps, &ps3)
	ps4 := certprotos.ProofStep{
		S1:          attestKeyIsTrusted,
		S2:          attestKeySaysEnclaveKeySpeaksForMeasurement,
		Conclusion:  enclaveKeySpeaksForMeasurement,
		RuleApplied: &r6,
	}
	p.Steps = append(p.Steps, &ps4)
	ps5 := certprotos.ProofStep{
		S1:          measurementIsTrusted,
		S2:          enclaveKeySpeaksForMeasurement,
		Conclusion:  enclaveKeyIsTrusted,
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
	var ipk string = "issuerKey"
	privateIssuerKey.KeyName = &ipk
	PrintKey(privateIssuerKey)
	// issuerKey := InternalPublicFromPrivateKey(privateIssuerKey)
	fmt.Println("\nIssuer key")
	PrintKey(privateIssuerKey)

	privateSubjKey := MakeVseRsaKey(2048)
	var spk string = "subjKey"
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
			CommonName: "testIssuer",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 86400 * 1000000000),
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
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

	remoteIP := "192.2.2.1"
	cert := ProduceAdmissionCert(remoteIP, privateIssuerKey, newParentCert, subjKey, "testSubject", "",
		uint64(5), 365.0*86400)
	fmt.Println("")
	if cert == nil {
		fmt.Println("ProduceArtifact returned nil")
	}
	//issuerName := GetIssuerNameFromCert(cert)
	subjName := GetSubjectNameFromCert(cert)
	if subjName != nil {
		fmt.Printf("Subject Name: %s\n", *subjName)
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

func (r *MyInt) Func2(in int) string {
	return fmt.Sprintf("***%d", in)
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

func TestEcc384(t *testing.T) {
	fmt.Printf("\nTestECC384\n")
	pK, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Errorf("ecdsa.GenerateKey fails\n")
		return
	}
	name := "test-key"
	k := new(certprotos.KeyMessage)
	PK := pK.Public()
	if !GetInternalKeyFromEccPublicKey(name, PK.(*ecdsa.PublicKey), k) {
		t.Errorf("GetInternalKeyFromEccPublicKey fails\n")
		return
	}
	PrintKey(k)
	_, new_PK, err := GetEccKeysFromInternal(k)
	if err != nil || new_PK == nil {
		t.Errorf("GetInternalKeyFromEccPublicKey fails\n")
		return
	}

	new_k := new(certprotos.KeyMessage)
	if !GetInternalKeyFromEccPublicKey(name, PK.(*ecdsa.PublicKey), new_k) {
		t.Errorf("GetInternalKeyFromEccPublicKey fails\n")
		return
	}
	PrintKey(new_k)
	if !SameKey(k, new_k) {
		t.Errorf("Translated key doesnt match\n")
		return
	}

	toHash := make([]byte, 50)
	for i := 0; i < 50; i++ {
		toHash[i] = byte(i)
	}
	hashed := sha512.Sum384(toHash)
	fmt.Printf("hashed: ")
	PrintBytes(hashed[0:])
	fmt.Printf("\n")
	r, s, err := ecdsa.Sign(rand.Reader, pK, hashed[0:])
	if err != nil {
		t.Errorf("Couldn't sign\n")
		return
	}
	if !ecdsa.Verify(PK.(*ecdsa.PublicKey), hashed[0:], r, s) {
		t.Errorf("Couldn't verify with old PK\n")
		return
	}
	fmt.Printf("\n\nr: ")
	fmt.Print(r)
	fmt.Printf("\n")
	fmt.Printf("s: ")
	fmt.Print(s)
	fmt.Printf("\nr: ")
	r_bytes := r.Bytes()
	PrintBytes(r_bytes)
	fmt.Printf("\ns: ")
	s_bytes := s.Bytes()
	PrintBytes(s_bytes)
	fmt.Printf("\n\n")
	fmt.Printf("New internal:\n")
	fmt.Print(new_PK)
	fmt.Printf("\n")
	fmt.Printf("X: ")
	fmt.Print(new_PK.X)
	fmt.Printf("\n")
	if !ecdsa.Verify(new_PK, hashed[0:], r, s) {
		t.Errorf("Couldn't verify with new PK\n")
		return
	}
	// certlib.VerifySevAttestation(serialized []byte, k *certprotos.KeyMessage) []byte

	new_name := "vcertKey"
	km := new(certprotos.KeyMessage)
	if !GetInternalKeyFromEccPublicKey(new_name, new_PK, km) {
		t.Errorf("Couldn't GetInternalKeyFromEccPublicKey\n")
		return
	}
	PrintKey(km)
	fmt.Printf("\n")

	_, recovered_PK, err := GetEccKeysFromInternal(km)
	if err != nil {
		t.Errorf("GetEccKeysFromInternal failed\n")
		return
	}

	new_km := new(certprotos.KeyMessage)
	if !GetInternalKeyFromEccPublicKey(new_name, recovered_PK, new_km) {
		t.Errorf("Couldn't GetInternalKeyFromEccPublicKey\n")
		return
	}
	PrintKey(new_km)
	fmt.Printf("\n")

	ttt := make([]byte, 48)
	for i := 0; i < 48; i++ {
		ttt[i] = byte(i)
	}
	fmt.Printf("One (%d): ", len(ttt[0:47]))
	PrintBytes(ttt[0:47])
	fmt.Printf("\n")
	fmt.Printf("Two (%d): ", len(ttt[0:48]))
	PrintBytes(ttt[0:48])
	fmt.Printf("\n")
}

func TestEcc256(t *testing.T) {
	fmt.Printf("\nTestECC256\n")
	pK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("ecdsa.GenerateKey fails\n")
		return
	}
	name := "test-key"
	k := new(certprotos.KeyMessage)
	PK := pK.Public()
	if !GetInternalKeyFromEccPublicKey(name, PK.(*ecdsa.PublicKey), k) {
		t.Errorf("GetInternalKeyFromEccPublicKey fails\n")
		return
	}
	PrintKey(k)
	_, new_PK, err := GetEccKeysFromInternal(k)
	if err != nil || new_PK == nil {
		t.Errorf("GetInternalKeyFromEccPublicKey fails\n")
		return
	}
	new_k := new(certprotos.KeyMessage)
	if !GetInternalKeyFromEccPublicKey(name, PK.(*ecdsa.PublicKey), new_k) {
		t.Errorf("GetInternalKeyFromEccPublicKey fails\n")
		return
	}
	PrintKey(new_k)
	if !SameKey(k, new_k) {
		t.Errorf("Translated key doesnt match\n")
		return
	}

	toHash := make([]byte, 50)
	for i := 0; i < 50; i++ {
		toHash[i] = byte(i)
	}
	hashed := sha256.Sum256(toHash)
	fmt.Printf("hashed: ")
	PrintBytes(hashed[0:])
	fmt.Printf("\n")

	r, s, err := ecdsa.Sign(rand.Reader, pK, hashed[0:])
	if err != nil {
		t.Errorf("Couldn't sign\n")
		return
	}
	if !ecdsa.Verify(PK.(*ecdsa.PublicKey), hashed[0:], r, s) {
		t.Errorf("Couldn't verify with old PK\n")
		return
	}
	fmt.Printf("\n\nr: ")
	fmt.Print(r)
	fmt.Printf("\n")
	fmt.Printf("s: ")
	fmt.Print(s)
	fmt.Printf("\nr: ")
	r_bytes := r.Bytes()
	PrintBytes(r_bytes)
	fmt.Printf("\ns: ")
	s_bytes := s.Bytes()
	PrintBytes(s_bytes)
	fmt.Printf("\n\n")
	fmt.Printf("New internal:\n")
	fmt.Print(new_PK)
	fmt.Printf("\n")
	fmt.Printf("X: ")
	fmt.Print(new_PK.X)
	fmt.Printf("\n")
	if !ecdsa.Verify(new_PK, hashed[0:], r, s) {
		t.Errorf("Couldn't verify with new PK\n")
		return
	}
	// certlib.VerifySevAttestation(serialized []byte, k *certprotos.KeyMessage) []byte

	new_name := "vcertKey"
	km := new(certprotos.KeyMessage)
	if !GetInternalKeyFromEccPublicKey(new_name, new_PK, km) {
		t.Errorf("Couldn't GetInternalKeyFromEccPublicKey\n")
		return
	}
	PrintKey(km)
	fmt.Printf("\n")

	_, recovered_PK, err := GetEccKeysFromInternal(km)
	if err != nil {
		t.Errorf("GetEccKeysFromInternal failed\n")
		return
	}

	new_km := new(certprotos.KeyMessage)
	if !GetInternalKeyFromEccPublicKey(new_name, recovered_PK, new_km) {
		t.Errorf("Couldn't GetInternalKeyFromEccPublicKey\n")
		return
	}
	PrintKey(new_km)
	fmt.Printf("\n")

	ttt := make([]byte, 32)
	for i := 0; i < 32; i++ {
		ttt[i] = byte(i)
	}
	fmt.Printf("One (%d): ", len(ttt[0:31]))
	PrintBytes(ttt[0:31])
	fmt.Printf("\n")
	fmt.Printf("Two (%d): ", len(ttt[0:32]))
	PrintBytes(ttt[0:32])
	fmt.Printf("\n")
}

func TestPEM(t *testing.T) {
	fmt.Printf("\nTestPEM\n")

	certFile := "vse.crt"
	certPem, err := os.ReadFile(certFile)
	if err != nil || certPem == nil {
		return // Todo: Remove
		t.Errorf("Can't read pem cert file\n")
		return
	}
	stripped := StripPemHeaderAndTrailer(string(certPem))
	if stripped == nil {
		t.Errorf("No headers?\n")
		return
	}
	fmt.Printf("PEM: %s\n", *stripped)
	k := KeyFromPemFormat(*stripped)
	if k == nil {
		t.Errorf("Can't retrieve key from pem cert\n")
		return
	}
	fmt.Printf("Key from pem cert\n")
	PrintKey(k)
	fmt.Printf("\n")
}

func TestPlatformPrimitives(t *testing.T) {
	fmt.Print("\nTestPlatformPrimitives\n")

	t1 := "amd-sev-snp"
	props := &certprotos.Properties{}
	name := "debug"
	t2 := "string"
	t3 := "int"
	sv := "no"
	c := "="
	iv := uint64(5)
	p1 := MakeProperty(name, t2, &sv, &c, nil)
	if p1 != nil {
		props.Props = append(props.Props, p1)
	}
	name2 := "api-major"
	p2 := MakeProperty(name2, t3, nil, &c, &iv)
	if p2 != nil {
		props.Props = append(props.Props, p2)
	}

	pl := MakePlatform(t1, nil, props)
	PrintPlatform(pl)

	measurement := []byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	}
	e := MakeEnvironment(pl, measurement)
	if e == nil {
		fmt.Printf("Can't make environment\n")
	} else {
		PrintEnvironment(e)
	}

	pe := MakePlatformEntity(pl)
	ee := MakeEnvironmentEntity(e)
	PrintEntity(pe)
	PrintEntity(ee)

	fmt.Printf("\n\nDescriptors:\n")
	PrintEntityDescriptor(ee)
	fmt.Printf("\n")
	PrintEntityDescriptor(pe)
	fmt.Printf("\n\n")

	if !SameProperty(p1, p1) {
		t.Errorf("Properties should match\n")
	}
	if SameProperty(p1, p2) {
		t.Errorf("Properties shouldn't match\n")
	}
	if !SameEnvironment(e, e) {
		t.Errorf("Environments should match\n")
	}

	pl2 := &certprotos.Platform{
		HasKey:       pl.HasKey,
		PlatformType: pl.PlatformType,
		AttestKey:    pl.AttestKey,
		Props:        pl.Props,
	}
	if !SamePlatform(pl, pl2) {
		t.Errorf("Platforms should match\n")
	}
	pl3, _ := proto.Clone(pl).(*certprotos.Platform)
	if !SamePlatform(pl, pl3) {
		t.Errorf("Platforms should match\n")
	}

	if !SatisfyingProperty(p1, p1) {
		t.Errorf("Properties should satisfy (1)\n")
	}
	if SatisfyingProperty(p1, p2) {
		t.Errorf("Properties shouldn't satisfy (1)\n")
	}
	properties := &certprotos.Properties{}
	properties.Props = append(properties.Props, p1)
	properties.Props = append(properties.Props, p2)
	if !SameProperties(properties, properties) {
		t.Errorf("Series of properties shouldn't match (2)\n")
	}
	if !SatisfyingProperties(properties, properties) {
		t.Errorf("Series of properties shouldn't satisfy (2)\n")
	}

	c3 := ">="
	p3 := MakeProperty(name2, t3, nil, &c3, &iv)
	props2 := &certprotos.Properties{}
	if p1 != nil {
		props2.Props = append(props2.Props, p1)
	}
	if p3 != nil {
		props2.Props = append(props2.Props, p3)
	}
	if !SatisfyingProperty(p3, p2) {
		t.Errorf("Properties should satisfy (3)\n")
		fmt.Printf("First\n")
		PrintProperty(p3)
		fmt.Printf("\n\n")
		fmt.Printf("Second\n")
		PrintProperty(p2)
		fmt.Printf("\n\n")
	}
	if SatisfyingProperty(p2, p3) {
		t.Errorf("Properties should satisfy (3)\n")
		fmt.Printf("First\n")
		PrintProperty(p3)
		fmt.Printf("\n\n")
		fmt.Printf("Second\n")
		PrintProperty(p2)
		fmt.Printf("\n\n")
	}
	if !SatisfyingProperties(props2, props) {
		t.Errorf("Series of properties shouldn't satisfy (3)\n")
		fmt.Printf("First List\n")
		PrintProperties(props)
		fmt.Printf("\n\n")
		fmt.Printf("Second List\n")
		PrintProperties(props2)
		fmt.Printf("\n\n")
	}

	/*
	     uint64_t    policy;                   // 0x008
	     uint8_t     report_data[64];          // 0x050
	     uint8_t     measurement[48];          // 0x090
	     union tcb_version reported_tcb;       // 0x180
	   };
	*/
	var ar [0x2A0]byte
	fakeSevAtt := []byte(ar[0:0x2a0])
	for i := 0; i < 0x2A0; i++ {
		fakeSevAtt[i] = 0
	}
	fakeSevAtt[8] = 0xff
	fakeSevAtt[0x50] = 0x01
	fakeSevAtt[0x51] = 0x01
	fakeSevAtt[0x52] = 0x01
	fakeSevAtt[0x53] = 0x01
	for i := 0; i < 48; i++ {
		fakeSevAtt[i+0x90] = byte(i)
	}
	m := GetMeasurementFromSevAttest(fakeSevAtt)
	if m == nil {
		t.Errorf("Can't get measurement")
	} else {
		fmt.Printf("Measurement: ")
		PrintBytes(m)
		fmt.Printf("\n")
	}
	ud := GetUserDataHashFromSevAttest(fakeSevAtt)
	if ud == nil {
		t.Errorf("Can't get user data")
	} else {
		fmt.Printf("User data: ")
		PrintBytes(ud)
		fmt.Printf("\n")
	}
	plat := GetPlatformFromSevAttest(fakeSevAtt)
	if plat == nil {
		t.Errorf("Can't get platform")
	} else {
		PrintPlatform(plat)
		fmt.Printf("\n")
	}

}

/*
func TestPlatformVerify(t *testing.T) {

        arkCertFile := "test_data/sev_ark_cert.der"
        askCertFile := "test_data/sev_ask_cert.der"
        vcekCertFile := "test_data/sev_vcek_cert.der"
        attestFile := "test_data/sev_attest.bin"
        policyFile := "test_data/sev_policy.bin"
        fmt.Printf("\nTestPlatformVerify %s %s %s %s\n", arkCertFile, askCertFile, vcekCertFile, attestFile)

        // Read attestation and certs
        arkCertDer, err := os.ReadFile(arkCertFile)
        if err != nil {
                t.Errorf("Can't read ark file")
		return
        }
        askCertDer, err := os.ReadFile(askCertFile)
        if err != nil {
                t.Errorf("Can't read ask file")
		return
        }
        vcekCertDer, err := os.ReadFile(vcekCertFile)
        if err != nil {
                t.Errorf("Can't read vcek file")
		return
        }
        attestBin, err := os.ReadFile(attestFile)
        if err != nil {
                t.Errorf("Can't read sev_attestation file")
		return
        }
        fmt.Printf("\narkCert:\n")
        PrintBytes(arkCertDer)
        fmt.Printf("\n")
        fmt.Printf("\naskCert:\n")
        PrintBytes(askCertDer)
        fmt.Printf("\n")
        fmt.Printf("\nvcekCert:\n")
        PrintBytes(vcekCertDer)
        fmt.Printf("\n")
        fmt.Printf("\nAttest:\n")
        PrintBytes(attestBin)
        fmt.Printf("\n")

        vseVe := "vse-verifier"
        et := "cert"
        ev1 := &certprotos.Evidence {
                EvidenceType: &et,
                SerializedEvidence: arkCertDer,
        }
        ev2 := &certprotos.Evidence {
                EvidenceType: &et,
                SerializedEvidence: askCertDer,
        }
        ev3 := &certprotos.Evidence {
                EvidenceType: &et,
                SerializedEvidence: vcekCertDer,
        }

        aet := "sev-attestation"
        ev4 := &certprotos.Evidence {
                EvidenceType: &aet,
                SerializedEvidence: attestBin,
        }

        evp := &certprotos.EvidencePackage {
                ProverType: &vseVe,
        }
        evp.FactAssertion = append(evp.FactAssertion, ev1)
        evp.FactAssertion = append(evp.FactAssertion, ev2)
        evp.FactAssertion = append(evp.FactAssertion, ev3)
        evp.FactAssertion = append(evp.FactAssertion, ev4)

        // Construct request
        reqTag := "requestor"
        provTag := "provider"
        evType := "sev-platform-package"
        pur := "authentication"
        req := &certprotos.TrustRequestMessage {
                RequestingEnclaveTag: &reqTag,
                ProvidingEnclaveTag: &provTag,
                SubmittedEvidenceType: &evType,
                Purpose: &pur,
                Support: evp,
        }
	fmt.Printf("\nRequest:\n")
        PrintTrustRequest(req)
	fmt.Printf("\n\n")

        sevAtt := &certprotos.SevAttestationMessage{}
        err = proto.Unmarshal(attestBin, sevAtt)
        if err != nil {
                t.Errorf("Can't unmarshal sev attestation\n")
		return
        }

	// Get policy Key from ud
	ud := &certprotos.AttestationUserData {}
        err = proto.Unmarshal(sevAtt.WhatWasSaid, ud)
        if err != nil {
                t.Errorf("Can't unmarshal what was said \n")
		return
        }

	fmt.Printf("\nUser data\n")
	PrintAttestationUserData(ud)

        // Read policy
        serializedPolicy, err := os.ReadFile(policyFile)
        if err != nil {
                t.Errorf("Can't read policy\n")
		return
        }
	signedPolicy := &certprotos.SignedClaimSequence{}
	err = proto.Unmarshal(serializedPolicy, signedPolicy)
	if err != nil {
                t.Errorf("Can't unmarshal signed policy\n")
		return
	}

	// initPolicy
	originalPolicy := &certprotos.ProvedStatements{}
	if !InitAxiom(*ud.PolicyKey, originalPolicy) {
		fmt.Printf("ValidateSevEvidence: Can't InitAxiom\n")
		return
	}

	if !InitPolicy(ud.PolicyKey, signedPolicy, originalPolicy) {
		fmt.Printf("ValidateSevEvidence: Can't init policy\n")
		return
	}

	// Validate
	success, toProve, measurement := ValidateSevEvidence(ud.PolicyKey, evp, originalPolicy, pur)
	if !success {
                fmt.Printf("ValidateSevEvidence fails\n")
		return
	}
	fmt.Printf("ValidateSevEvidence succeeds\n")
	fmt.Printf("Proved: ");
	PrintVseClause(toProve)
	fmt.Printf("\n")
	fmt.Printf("Measurement: ");
	PrintBytes(measurement)
	fmt.Printf("\n")
}
*/

// For Sev testing --- deprecated
/*
func TestSevSignatures(t *testing.T) {
        fmt.Printf("\nTestSevSignatures\n")

        certFile := "vcek.der"
        certDer, err := os.ReadFile(certFile)
        if err != nil {
                fmt.Println("Can't read key file, ", err)
        }
        cert := Asn1ToX509(certDer)
        if cert == nil {
                t.Errorf("Can't turn der into cert\n")
                return
        }
        repFile := "guest_report.bin"
        report, err := os.ReadFile(repFile)
        if err != nil {
                t.Errorf("Can't read report file\n")
                return
        }

        fmt.Printf("Report (%x):\n", len(report))
        PrintBytes(report)
        fmt.Printf("\n")
        fmt.Printf("Header (%x):\n", 0x2a0)
        PrintBytes(report[0:0x2a0])
        fmt.Printf("\n")
        fmt.Printf("signature:\n    ")
        PrintBytes(report[0x2a0:0x2d0])
        fmt.Printf("\n    ")
        PrintBytes(report[0x2e8:0x318])
        fmt.Printf("\n")

        hashOfHeader := sha512.Sum384(report[0:0x2a0])

        fmt.Printf("hash of header (%d): ", len(hashOfHeader))
        PrintBytes(hashOfHeader[0:48])
        fmt.Printf("\n")

        k := GetSubjectKey(cert)
        if k == nil {
                t.Errorf("Can't get subject Key\n")
                return
        }

        PrintKey(k)
        fmt.Printf("\n")

        _, PK, err := GetEccKeysFromInternal(k)
        if err!= nil || PK == nil {
                t.Errorf("Can't extract key from Internal.\n")
                return
        }

        PKecc, ok := cert.PublicKey.(*ecdsa.PublicKey)
        if !ok {
                t.Errorf("Can't get key from cert.\n")
                return
        }

        be_r_bytes :=  LittleToBigEndian(report[0x2a0:0x2d0])
        be_s_bytes :=  LittleToBigEndian(report[0x2e8:0x318])

        fmt.Printf("signature (be):\n    ")
        PrintBytes(be_r_bytes)
        fmt.Printf("\n    ")
        PrintBytes(be_s_bytes)
        fmt.Printf("\n")

        if  be_r_bytes == nil || be_s_bytes == nil {
                t.Errorf("Can't convert to big endian.\n")
                return
        }
        r :=  new(big.Int).SetBytes(be_r_bytes)
        s :=  new(big.Int).SetBytes(be_s_bytes)

        fmt.Printf("r: ")
        fmt.Print(r)
        fmt.Printf("\n")
        fmt.Printf("s: ")
        fmt.Print(s)
        fmt.Printf("\n")

        if !ecdsa.Verify(PKecc, hashOfHeader[0:48], r, s) {
                fmt.Printf("Does NOT verify\n")
                return
        }
        fmt.Printf("VERIFIES\n")
        return
}
*/

/*
func TestGramineVerify(t *testing.T) {

        policyKeyFile := "test_data/policy_key_file.bin"
        enclaveKeyFile := "test_data/attest_key_file.bin"
        intelCertFile := "test_data/intel_cert.der"
        attestFile := "test_data/attest_file.bin"
        fmt.Printf("\nTestGramineVerify %s %s %s\n", policyKeyFile, intelCertFile, attestFile)

	// Read policy key and unmarshal
        serializedPolicyKey, err := os.ReadFile(policyKeyFile)
        if err != nil {
                t.Errorf("Can't read policy key file")
		return
        }
        policyKey := certprotos.KeyMessage {}
        err = proto.Unmarshal(serializedPolicyKey, &policyKey)
        if err != nil {
                t.Errorf("Can't unmarshal policy key\n")
		return
        }

	// Read enclave key and unmarshal
        serializedEnclaveKey, err := os.ReadFile(enclaveKeyFile)
        if err != nil {
                t.Errorf("Can't read enclave key file")
		return
        }
        enclaveKey := certprotos.KeyMessage {}
        err = proto.Unmarshal(serializedEnclaveKey, &enclaveKey)
        if err != nil {
                t.Errorf("Can't unmarshal enclave key\n")
		return
        }

        // Read cert and binary attestation
        intelCertDer, err := os.ReadFile(intelCertFile)
        if err != nil {
                t.Errorf("Can't read intel file")
		return
        }
        gramineAttestBin, err := os.ReadFile(attestFile)
        if err != nil {
                t.Errorf("Can't read gramine attestation file")
		return
        }

	// User data
	ud := &certprotos.AttestationUserData {}

	enclaveType := "gramine-enclave"
	ud.EnclaveType = &enclaveType
	tn := TimePointNow()
	strTn := TimePointToString(tn)
	ud.Time = &strTn
	ud.EnclaveKey = &enclaveKey
	ud.PolicyKey = &policyKey

	fmt.Printf("\nUser data\n")
	PrintAttestationUserData(ud)

	// Serialize User Data
	serializedUD, err := proto.Marshal(ud)
	if err != nil {
                t.Errorf("Can't serialize user data")
		return
	}

	// GramineAttestationMessage
        gramineAttMsg := &certprotos.GramineAttestationMessage{}
	gramineAttMsg.WhatWasSaid = serializedUD
	gramineAttMsg.ReportedAttestation = gramineAttestBin

	serializedGramineAttestMsg, err := proto.Marshal(gramineAttMsg)
	if err != nil {
                t.Errorf("Can't serialized gramine attest message")
		return
	}

        fmt.Printf("\nintelCert:\n")
        PrintBytes(intelCertDer)
        fmt.Printf("\n")
        fmt.Printf("\nGramine Attest:\n")
        PrintBytes(gramineAttestBin)
        fmt.Printf("\n")
        fmt.Printf("\nSerialized Gramine attest:\n")
        PrintBytes(serializedGramineAttestMsg)
        fmt.Printf("\n")

	// fake measurement for now
	m := make([]byte, 48)
	for i := 0; i < 48; i++ {
		m[i] = byte(i)
	}

        vseVe := "vse-verifier"
        et := "cert"
        ev1 := &certprotos.Evidence {
                EvidenceType: &et,
                SerializedEvidence: intelCertDer,
        }
        aet := "gramine-attestation"
        ev2 := &certprotos.Evidence {
                EvidenceType: &aet,
                SerializedEvidence: serializedGramineAttestMsg,
        }

        evp := &certprotos.EvidencePackage {
                ProverType: &vseVe,
        }
        evp.FactAssertion = append(evp.FactAssertion, ev1)
        evp.FactAssertion = append(evp.FactAssertion, ev2)

        // Construct request
        reqTag := "requestor"
        provTag := "provider"
        evType := "gramine-evidence"
        pur := "authentication"
        req := &certprotos.TrustRequestMessage {
                RequestingEnclaveTag: &reqTag,
                ProvidingEnclaveTag: &provTag,
                SubmittedEvidenceType: &evType,
                Purpose: &pur,
                Support: evp,
        }
	fmt.Printf("\nRequest:\n")
        PrintTrustRequest(req)
	fmt.Printf("\n\n")


	// Write policy
	//	1. policyKey says intelKey is-trusted-for-attestation
	//	2. policyKey says measurement is-trusted
	publicPolicyKey := InternalPublicFromPrivateKey(&policyKey)
        if publicPolicyKey == nil {
                t.Errorf("Can't make public policy key\n")
		return
        }
        e1 := MakeKeyEntity(publicPolicyKey)
        if e1 == nil {
                t.Errorf("Can't make public policy entity\n")
		return
        }
	intelCert := Asn1ToX509(intelCertDer)
        if intelCert == nil {
                t.Errorf("Can't make oublic policy key\n")
		return
        }
	intelKey := GetSubjectKey(intelCert)
        if intelKey == nil {
                t.Errorf("Can't make intel key\n")
		return
        }
        e2 := MakeKeyEntity(intelKey)
        if e2 == nil {
                t.Errorf("Can't make intel key entity\n")
		return
        }
	t_verb := "is-trusted-for-attestation"
        c1 := MakeUnaryVseClause(e2, &t_verb)
        if c1 == nil {
                t.Errorf("Can't make unary clause 1\n")
		return
        }

        saysVerb := "says"
        c2 := MakeIndirectVseClause(e1, &saysVerb, c1)
        if c2 == nil {
                t.Errorf("Can't make indirect clause 1\n")
		return
        }

        tf := TimePointPlus(tn, 365 * 86400)
        nb := TimePointToString(tn)
        na := TimePointToString(tf)
        rule1, err := proto.Marshal(c2)
        if err != nil {
                t.Errorf("Can't serialize first rule\n")
		return
        }
        cl1 := MakeClaim(rule1, "vse-clause", "platform-rule", nb, na)
        if cl1 == nil {
                t.Errorf("Can't serialize first claim\n")
		return
        }
	sc1 := MakeSignedClaim(cl1, &policyKey)
        if sc1 == nil {
                t.Errorf("Can't sign first rule\n")
		return
        }

        e3 := MakeMeasurementEntity(m)
        if e3 == nil {
                t.Errorf("Can't make measurement entity\n")
		return
        }
	t2_verb := "is-trusted"
        c3 := MakeUnaryVseClause(e3, &t2_verb)
        if c1 == nil {
                t.Errorf("Can't make unary clause 2\n")
		return
        }

        c4 := MakeIndirectVseClause(e1, &saysVerb, c3)
        if c4 == nil {
                t.Errorf("Can't make indirect clause 2\n")
		return
        }

        rule2, err := proto.Marshal(c4)
        if err != nil {
                t.Errorf("Can't serialize second rule\n")
		return
        }
        cl2 := MakeClaim(rule2, "vse-clause", "measurement-rule", nb, na)
        if cl2 == nil {
                t.Errorf("Can't serialize second claim\n")
		return
        }
	sc2 := MakeSignedClaim(cl2, &policyKey)
        if sc2 == nil {
                t.Errorf("Can't sign second rule\n")
		return
        }

	fmt.Printf("Policy 1:\n")
	PrintSignedClaim(sc1)
	fmt.Printf("\nPolicy 2:\n")
	PrintSignedClaim(sc2)
	fmt.Printf("\n")

	fmt.Printf("Vse policy 1:\n")
	PrintVseClause(c2)
	fmt.Printf("\nVse policy 2:\n")
	PrintVseClause(c4)
	fmt.Printf("\n")

	alreadyProved := &certprotos.ProvedStatements{}
	if !InitAxiom(*publicPolicyKey, alreadyProved) {
                t.Errorf("Can't InitAxiom\n")
		return
	}

	alreadyProved.Proved = append(alreadyProved.Proved, c2)
	alreadyProved.Proved = append(alreadyProved.Proved, c4)

	publicEnclaveKey := InternalPublicFromPrivateKey(&enclaveKey)
        if publicPolicyKey == nil {
                t.Errorf("Can't make public policy key\n")
		return
        }
	c5:= ConstructGramineClaim(publicEnclaveKey, m)
        if c5 == nil {
                t.Errorf("Can't construct gramine claim\n")
		return
        }

	alreadyProved.Proved = append(alreadyProved.Proved, c5)
	fmt.Printf("\nProved on entry\n")
	for i := 0; i < len(alreadyProved.Proved);  i++ {
		fmt.Printf("%02d: ", i)
		PrintVseClause(alreadyProved.Proved[i])
		fmt.Printf("\n")
	}

	// Validate
	success, toProve, measurement := ValidateGramineEvidence(&policyKey, evp, alreadyProved, pur)
	if !success {
                fmt.Printf("ValidateGramineEvidence fails\n")
		return
	}
	fmt.Printf("ValidateGramineEvidence succeeds\n")
	fmt.Printf("Proved: ");
	PrintVseClause(toProve)
	fmt.Printf("\n")
	fmt.Printf("Measurement: ");
	PrintBytes(measurement)
	fmt.Printf("\n")
}
*/

func TestPolicyStore(t *testing.T) {

	fmt.Printf("\nPolicy Store Test\n")

	ps := NewPolicyStore(100)
	if ps == nil {
		t.Errorf("Can't create policy store")
		return
	}
	v1 := []byte{1, 2, 3, 4}
	e1 := NewPolicyStoreEntry("v1", "binary", v1)
	if e1 == nil {
		t.Errorf("Can't create e1")
		return
	}
	PrintPolicyStoreEntry(e1)
	v2 := []byte{1, 2, 3, 4, 5}
	e2 := NewPolicyStoreEntry("v2", "binary", v2)
	if e2 == nil {
		t.Errorf("Can't create e2")
		return
	}
	v3 := []byte{1, 2, 3, 4, 5, 6}
	e3 := NewPolicyStoreEntry("v3", "binary", v3)
	if e3 == nil {
		t.Errorf("Can't create e3")
		return
	}

	if !InsertOrUpdatePolicyStoreEntry(ps, "v1", "binary", v1) {
		t.Errorf("Can't add v1 to store")
		return
	}
	if !InsertOrUpdatePolicyStoreEntry(ps, "v2", "binary", v2) {
		t.Errorf("Can't add v1 to store")
		return
	}
	if !InsertOrUpdatePolicyStoreEntry(ps, "v3", "binary", v3) {
		t.Errorf("Can't add v1 to store")
		return
	}

	pk := MakeVseRsaKey(2048)
	serializedpk, err := proto.Marshal(pk)
	if err != nil {
		t.Errorf("Can't serialize key")
		return
	}
	if !InsertOrUpdatePolicyStoreEntry(ps, "policy-key", "key", serializedpk) {
		t.Errorf("Can't add policy key to store")
		return
	}

	ent := FindPolicyStoreEntry(ps, "v1", "binary")
	if ent < 0 {
		t.Errorf("Can't find v1 in store")
		return
	}
	if !bytes.Equal(ps.Entries[ent].Value, v1) {
		t.Errorf("v1 values don't match")
		return
	}

	fmt.Printf("\nPolicy Store:\n")
	PrintPolicyStore(ps)

	enclaveType := "simulated-enclave"

	if !SavePolicyStore(enclaveType, ps, "test_data/policy_store") {
		t.Errorf("Can't save policy store")
		return
	}

	psNew := new(certprotos.PolicyStoreMessage)
	if !RecoverPolicyStore(enclaveType, "test_data/policy_store", psNew) {
		t.Errorf("Can't recover policy store")
		return
	}

	if PolicyStoreNumEntries(ps) != PolicyStoreNumEntries(psNew) {
		t.Errorf("Recovered policy store has wrong number of messages")
		return
	}

	if ps.Entries[0].GetTag() != psNew.Entries[0].GetTag() ||
		ps.Entries[0].GetType() != psNew.Entries[0].GetType() ||
		!bytes.Equal(ps.Entries[0].Value, psNew.Entries[0].Value) {
		t.Errorf("Recovered policy store entry mismatch")
		return
	}

	newKey := new(certprotos.KeyMessage)
	err = proto.Unmarshal(psNew.Entries[3].Value, newKey)
	if err != nil {
		t.Errorf("Can't unmarshal key")
		return
	}
	if !SameKey(pk, newKey) {
		t.Errorf("Stored key doesn't match")
		return
	}

	fmt.Printf("\nRecovered key:\n")
	PrintKey(newKey)
}

/*
func TestTEESeal2(t *testing.T) {
	fmt.Print("\nTestTEESeal\n")

	var in []byte
	in = make([]byte, 32)
	for i := 0; i < 32; i++ {
		in[i] = byte((7 * i) % 16)
	}

	blank := ""
	err := TEESimulatedInit(blank, "test_data/attest_key_file.bin", "test_data/meas.bin", "test_data/platform_attest_endorsement.bin")
	if err != nil {
		t.Errorf("failed to initialize simulated enclave")
	}

	cipher, err := TEESeal("simulated-enclave", "test-enclave", in, 256)
	if err != nil {
		fmt.Printf("TEESeal failed: %s\n", err.Error())
		t.Errorf("TestTEESeal failed")
	}
	fmt.Printf("Cipher text length: %d\n", len(cipher))

	clear, err := TEEUnSeal("simulated-enclave", "test-enclave", cipher, 128)
	if err != nil {
		fmt.Printf("TEEUnseal failed: %s\n", err.Error())
		t.Errorf("TestTEESeal failed")
	}
	fmt.Printf("Clear text length: %d\n", len(clear))
	if !bytes.Equal(in, clear) {
		fmt.Printf("Clear text mismatch\n")
		t.Errorf("TestTEESeal failed")
	}
}
*/

func TestEncapsulatedData(t *testing.T) {
	fmt.Print("\nTestEncapsulatedData\n")

	rsaKey := MakeRsaKey(4096)
	if rsaKey == nil {
		t.Errorf("Can't generate Rsa key")
	}
	privK := certprotos.KeyMessage{}
	if !GetInternalKeyFromRsaPrivateKey("encapsulating-key", rsaKey, &privK) {
		t.Errorf("Can't Convert to private internal key")
	}
	PrintKey(&privK)
	fmt.Printf("\n")
	pubK := InternalPublicFromPrivateKey(&privK)
	if pubK == nil {
		t.Errorf("Can't Convert private to public internal key")
	}
	alg := "aes-256-gcm"
	data := []byte("Fourscore and seven years ago ... and now look")

	edm := certprotos.EncapsulatedDataMessage{}
	if !EncapsulateData(pubK, alg, data, &edm) {
		t.Errorf("Can't encapsulate data")
	}

	out := DecapsulateData(&privK, &edm)
	if out == nil {
		t.Errorf("Can't decapsulate data")
	}
	fmt.Printf("Out: %s\n", string(out))
}

/*
	Comment back in when CI scripts are updated

func TestSgxProperties(t *testing.T) {

	attestation, err := os.ReadFile("test_data/gramine-attestation.bin")
	if err != nil {
		fmt.Printf("Failed to read attestation file: %s\n", err.Error())
	}

	fmt.Printf("\nAttestation:\n")
	PrintBytes(attestation)
	fmt.Printf("\n\n")

	qeSvn, pceSvn, cpuSvn, debug, mode64bit := GetPlatformAttributesFromGramineAttest(attestation)
	fmt.Printf("cpuSvn: ")
	PrintBytes(cpuSvn)
	fmt.Printf("\n")

	platName := "sgx"
	cpuSvnName := "cpusvn"
	qeName := "quoting-enclave-sv"
	peName := "provisioning-enclave-sv"
	deName := "debug"
	x64Name := "X64"

	deVal := "no"
	if debug {
		deVal = "yes"
	}

	x64Val := "no"
	if mode64bit {
		x64Val = "yes"
	}

	props := &certprotos.Properties{}

	// Debug property
	p0 := MakeProperty(deName, "string", &deVal, nil, nil)
	props.Props = append(props.Props, p0)

	// 64 bit property
	p1 := MakeProperty(x64Name, "string", &x64Val, nil, nil)
	props.Props = append(props.Props, p1)

	ce := "="

	// qe property
	qeVal := uint64(qeSvn)
	p2 := MakeProperty(qeName, "int", nil, &ce, &qeVal)
	props.Props = append(props.Props, p2)

	// pe property
	peVal := uint64(pceSvn)
	p3 := MakeProperty(peName, "int", nil, &ce, &peVal)
	props.Props = append(props.Props, p3)

	// svn property
	svnVal := BytesToUint64(cpuSvn)
	p4 := MakeProperty(cpuSvnName, "int", nil, &ce, &svnVal)
	props.Props = append(props.Props, p4)

	var k *certprotos.KeyMessage = nil

	fmt.Printf("\n")
	fmt.Printf("svnVal: %x\n\n", svnVal)
	pl := MakePlatform(platName, k, props)
	PrintPlatform(pl)

	fmt.Printf("\nAttestation (%d): ", len(attestation))
	PrintBytes(attestation)
	fmt.Printf("\n")

	measurement := attestation[112:144]
	if measurement == nil {
		t.Errorf("Empty measurement\n")
	}
	fmt.Printf("\nMeasurement (%d):\n", len(measurement))
	PrintBytes(measurement)
	fmt.Printf("\n")

	reportData := attestation[368:432]
	fmt.Printf("\nReport data (%d):\n", len(reportData))
	PrintBytes(reportData)
	fmt.Printf("\n")

	e := MakeEnvironment(pl, measurement)
	if e == nil {
		fmt.Printf("Can't make environment\n")
	} else {
		PrintEnvironment(e)
	}
	fmt.Printf("\n")

	pe := MakePlatformEntity(pl)
	ee := MakeEnvironmentEntity(e)
	fmt.Printf("\n")
	PrintEntity(pe)
	PrintEntity(ee)
	fmt.Printf("\n")
	if !SameProperty(p1, p1) {
		t.Errorf("Properties should match\n")
	}
	if SameProperty(p1, p2) {
		t.Errorf("Properties shouldn't match\n")
	}
	if !SameEnvironment(e, e) {
		t.Errorf("Environments should match\n")
	}

	verbie := "is-environment"
	cl := MakeUnaryVseClause(ee, &verbie)
	fmt.Printf("\n")
	PrintVseClause(cl)
	fmt.Printf("\n")

	// evidence will include:
	//	attest-key says environment(platform, measurement) is-environment
	serializedKey, err := os.ReadFile("test_data/attest_key_file.bin")
	if err != nil {
		t.Errorf("Failed to read attest key file\n")
	}
	enclaveKey := certprotos.KeyMessage{}
	err = proto.Unmarshal(serializedKey, &enclaveKey)
	if err != nil {
		t.Errorf("Failed to deserialize attest key file\n")
	}

	sfc := ConstructGramineSpeaksForClaim(&enclaveKey, ee)
	if sfc == nil {
		t.Errorf("Can't construct speaks-for claim\n")
	}
	ec := ConstructGramineIsEnvironmentClaim(measurement, attestation)
	if ec == nil {
		t.Errorf("Can't construct is environment claim\n")
	}

	fmt.Printf("\n")
	fmt.Printf("\nEnvironment claim: ")
	PrintVseClause(ec)
	fmt.Printf("\n")
	fmt.Printf("\nSpeaks for claim: ")
	PrintVseClause(sfc)
	fmt.Printf("\n")
}

func TestSgxProofs(t *testing.T) {
	fmt.Printf("\n")
	fmt.Printf("\n")
	fmt.Printf("TestSgxProofs\n")
	fmt.Printf("\n")

	attestation, err := os.ReadFile("test_data/gramine-attestation.bin")
	if err != nil {
		t.Errorf("Failed to read attestation file\n")
	}

	serializedPolicyKey, err := os.ReadFile("test_data/policy_key_file.bin")
	if err != nil {
		t.Errorf("Failed to read policy key file\n")
	}
	policyPrivateKey := certprotos.KeyMessage{}
	err = proto.Unmarshal(serializedPolicyKey, &policyPrivateKey)
	if err != nil {
		t.Errorf("Failed to deserialize policy key file\n")
	}

	serializedEnclaveKey, err := os.ReadFile("test_data/attest_key_file.bin")
	if err != nil {
		t.Errorf("Failed to read enclave key file\n")
	}
	enclavePrivateKey := certprotos.KeyMessage{}
	err = proto.Unmarshal(serializedEnclaveKey, &enclavePrivateKey)
	if err != nil {
		t.Errorf("Failed to deserialize enclave key file\n")
	}

	policyKey := InternalPublicFromPrivateKey(&policyPrivateKey)
	if policyKey == nil {
		t.Errorf("Failed to convert policy key\n")
	}
	enclaveKey := InternalPublicFromPrivateKey(&enclavePrivateKey)
	if enclaveKey == nil {
		t.Errorf("Failed to convert enclave key\n")
	}

	// Evidence should be
	//    0. Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] is-trusted
	//    1. Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
	//        Key[rsa, platformKey, cdc8112d97fce6767143811f0ed5fb6c21aee424] is-trusted-for-attestation
	//    2. Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
	//        Measurement[0001020304050607...] is-trusted
	//    3. Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
	//        platform has-trusted-platform-property
	//    4. environment(platform, measurement) is-environment
	//    5. enclaveKey speaks-for Measurement[00010203...]

	pke := MakeKeyEntity(policyKey)
	if pke == nil {
		t.Errorf("Failed to make policy key entity\n")
	}
	eke := MakeKeyEntity(enclaveKey)
	if eke == nil {
		t.Errorf("Failed to make enclave key entity\n")
	}
	m := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	me := MakeMeasurementEntity(m)
	if me == nil {
		t.Errorf("Failed to make measurement entity\n")
	}

	p := GetPlatformFromGramineAttest(attestation)
	pe := MakePlatformEntity(p)
	env := MakeEnvironment(p, m)
	enve := MakeEnvironmentEntity(env)

	verbIsTrusted := "is-trusted"
	verbIsTrustedForAttestation := "is-trusted-for-attestation"
	verbSays := "says"
	verbSpeaksFor := "speaks-for"
	verbIsEnvironment := "is-environment"
	verbTrustedProperty := "has-trusted-platform-property"

	policyKeyIsTrusted := MakeUnaryVseClause(pke, &verbIsTrusted)
	keyIsTrustedForAttestation := MakeUnaryVseClause(eke, &verbIsTrustedForAttestation)
	policyKeySaysPlatformKeyIsTrustedForAttestation := MakeIndirectVseClause(pke, &verbSays, keyIsTrustedForAttestation)
	measurementIsTrusted := MakeUnaryVseClause(me, &verbIsTrusted)
	policyKeySaysMeasurementIsTrusted := MakeIndirectVseClause(pke, &verbSays, measurementIsTrusted)
	platformIsTrusted := MakeUnaryVseClause(pe, &verbTrustedProperty)
	policyKeySaysPlatformIsTrusted := MakeIndirectVseClause(pke, &verbSays, platformIsTrusted)
	environmentIsEnvironment := MakeUnaryVseClause(enve, &verbIsEnvironment)
	enclaveKeySpeaksForEnvironment := MakeSimpleVseClause(eke, &verbSpeaksFor, enve)

	alreadyProved := certprotos.ProvedStatements{}

	alreadyProved.Proved = append(alreadyProved.Proved, policyKeyIsTrusted)
	alreadyProved.Proved = append(alreadyProved.Proved, policyKeySaysPlatformKeyIsTrustedForAttestation)
	alreadyProved.Proved = append(alreadyProved.Proved, policyKeySaysMeasurementIsTrusted)
	alreadyProved.Proved = append(alreadyProved.Proved, policyKeySaysPlatformIsTrusted)
	alreadyProved.Proved = append(alreadyProved.Proved, policyKeySaysPlatformKeyIsTrustedForAttestation)
	alreadyProved.Proved = append(alreadyProved.Proved, environmentIsEnvironment)
	alreadyProved.Proved = append(alreadyProved.Proved, enclaveKeySpeaksForEnvironment)

	fmt.Printf("\n")
	purpose := "authentication"
	toProve, proof := ConstructProofFromExtendedGramineEvidence(policyKey, purpose, &alreadyProved)
	if toProve == nil || proof == nil {
		t.Errorf("Failed to ConstructProof\n")
	}

	fmt.Printf("\n")
	fmt.Printf("toProve: ")
	PrintVseClause(toProve)
	fmt.Printf("\n")

	fmt.Printf("\n")
	PrintProof(proof)

	if VerifyProof(policyKey, toProve, proof, &alreadyProved) {
		fmt.Printf("Proof succeeded\n")
	} else {
		fmt.Printf("Proof failed\n")
	}
}
*/
