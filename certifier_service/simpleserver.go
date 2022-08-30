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
//
// File: simpleserver.go

package main

import (
	"bytes"
        "crypto/x509"
	//"crypto/rsa"
	"flag"
	"fmt"
	"encoding/hex"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/golang/protobuf/proto"
	certprotos "github.com/jlmucb/crypto/v2/certifier-framework-for-confidential-computing/certifier_service/certprotos"
	certlib "github.com/jlmucb/crypto/v2/certifier-framework-for-confidential-computing/certifier_service/certlib"
)

var simpleServerPath = flag.String("path", "./SimpleServerFiles",
	"path to Server files")
var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")

var policyKeyFile = flag.String("policy_key_file", "policy_key_file.bin", "key file name")
var policyCertFile = flag.String("policy_cert_file", "policy_cert_file.bin", "cert file name")
var readPolicy = flag.Bool("readPolicy", true, "read policy")
var policyFile = flag.String("policyFile", "./certlib/policy.bin", "policy file name")
var loggingSequenceNumber = *flag.Int("loggingSequenceNumber", 1,  "sequence number for logging")

var enableLog = flag.Bool("enableLog", false, "enable logging")
var logDir = flag.String("logDir", ".", "log directory")
var logFile = flag.String("logFile", "simpleserver.log", "log file name")

var privatePolicyKey certprotos.KeyMessage
var publicPolicyKey *certprotos.KeyMessage = nil
var serializedPolicyCert []byte
var policyCert *x509.Certificate = nil
var sn uint64 = uint64(time.Now().UnixNano())
var duration float64 = 365.0 * 86400

var logging bool = false
var logger *log.Logger
var dataPacketFileNum int = loggingSequenceNumber
func initLog() bool {
	name := *logDir + "/" + *logFile
	logFiled, err := os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Printf("Can't open log file\n")
		return false
	}
	logger = log.New(logFiled, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	logger.Println("Starting simpleserver")
	return true
}


var policyInitialized bool = false
var signedPolicyStatements *certprotos.SignedClaimSequence = nil

// There are really only two kinds of initialzed policy now:
//	policy-key says Measurement[] is-trusted
//	policy-key says Key[] is-trusted-for-attestation

type measurementPolicyStatement struct {
	m []byte
	sc certprotos.SignedClaimMessage
}
type platformPolicyStatement struct {
	pk  certprotos.KeyMessage
	sc certprotos.SignedClaimMessage
}

// These are the policy approved program measurements and platform keys.
var measurementList []measurementPolicyStatement
var platformList []platformPolicyStatement

func findPolicyFromMeasurement(m []byte) *certprotos.SignedClaimMessage {
	for i := 0; i < len(measurementList); i++ {
		if bytes.Equal(m, measurementList[i].m) {
			return &measurementList[i].sc
		}
	}
	return nil
}

func findPolicyFromKey(k *certprotos.KeyMessage) *certprotos.SignedClaimMessage {
	for i := 0; i < len(platformList); i++ {
		if certlib.SameKey(k, &platformList[i].pk) {
			return &platformList[i].sc
		}
	}
	return nil
}

func initPolicy(thePolicyFile string) bool {

	// Debug
	fmt.Printf("initPolicy\n")

	policySeq, err := os.ReadFile(thePolicyFile)
	if err != nil {
		fmt.Println("can't read policy file, ", err)
		return false
	}

	// Debug
	fmt.Printf("Read %d bytes\n", len(policySeq))

	var  claimBlocks *certprotos.BufferSequence = &certprotos.BufferSequence{}
	err = proto.Unmarshal(policySeq, claimBlocks)
	if err != nil {
		fmt.Println("can't parse policy file, ", err)
		return false
	}

	// Debug
	fmt.Printf("%d policy statements\n", len (claimBlocks.Block))

	for i := 0; i < len(claimBlocks.Block); i++ {
		var sc *certprotos.SignedClaimMessage =  &certprotos.SignedClaimMessage{}
		err = proto.Unmarshal(claimBlocks.Block[i], sc)
		if err != nil {
			fmt.Println("can't recover policy rule, ", err)
			return false
		}
		vse := certlib.GetVseFromSignedClaim(sc)
		if vse == nil {
			continue
		}
		if vse.Subject == nil || vse.Verb == nil || vse.Clause == nil {
			continue
		}
		if *vse.Verb != "says" {
			continue
		}
		if vse.Clause.Subject ==nil || vse.Clause.Verb == nil {
			continue
		}

		if *vse.Clause.Verb == "is-trusted-for-attestation" &&
				vse.Clause.Subject.GetEntityType() == "key" {
			ps := platformPolicyStatement {
				pk: *vse.Clause.Subject.Key,
				sc:  *sc,
			}
			platformList = append(platformList, ps)
		} else if  *vse.Clause.Verb == "is-trusted" &&
			vse.Clause.Subject.GetEntityType() == "measurement" {
			ps := measurementPolicyStatement {
				m: vse.Clause.Subject.Measurement,
				sc:  *sc,
			}
			measurementList = append(measurementList, ps)
		} else {
			continue
		}
	}

	// Debug
	fmt.Printf("\nMeasurement list, %d entries:\n", len(measurementList))
	for i := 0; i < len(measurementList); i++ {
		fmt.Printf("\n")
		certlib.PrintBytes(measurementList[i].m)
		fmt.Printf("\n")
		certlib.PrintSignedClaim(&measurementList[i].sc)
		fmt.Printf("\n")
	}
	fmt.Printf("\nPlatform list, %d entries:\n", len(platformList))
	for i := 0; i < len(platformList); i++ {
		fmt.Printf("\n")
		certlib.PrintKey(&platformList[i].pk)
		fmt.Printf("\n")
		certlib.PrintSignedClaim(&platformList[i].sc)
		fmt.Printf("\n")
	}
	return true
}

// At init, we retrieve the policy key and the rules to evaluate
func initCertifierService() bool {
	// Debug
	fmt.Printf("initCertifierService, Policy key file: %s, Policy cert file: %s\n", *policyKeyFile, *policyCertFile)

	if *enableLog {
		logging = initLog()
	}

	serializedKey, err := os.ReadFile(*policyKeyFile)
	if err != nil {
		fmt.Println("can't read key file, ", err)
		return false
	}

	serializedPolicyCert, err := os.ReadFile(*policyCertFile)
	if err != nil {
		fmt.Println("can't certkey file, ", err)
	}
	policyCert, err = x509.ParseCertificate(serializedPolicyCert)
	if err != nil {
		fmt.Println("Can't Parse policy cert, ", err)
		return false
	}

	err = proto.Unmarshal(serializedKey, &privatePolicyKey)
	if err != nil {
		return false
	}

	publicPolicyKey = certlib.InternalPublicFromPrivateKey(&privatePolicyKey)
	if publicPolicyKey == nil {
		return false
	}

	if *readPolicy && policyFile != nil {
		policyInitialized = initPolicy(*policyFile)
		if !policyInitialized {
			fmt.Printf("Error: Couldn't initialize policy\n")
			return false
		}
	} else {
		fmt.Printf("Error: readPolicy must be true\n")
		return false
	}

	if !certlib.InitSimulatedEnclave() {
		return false
	}
	return true
}

func AddFactFromSignedClaim(signedClaim *certprotos.SignedClaimMessage,
		alreadyProved *certprotos.ProvedStatements) bool {

	k := signedClaim.SigningKey
	tcl := certprotos.VseClause{}
	if certlib.VerifySignedAssertion(*signedClaim, k, &tcl) {
		// make sure the saying key in tcl is the same key that signed it
		if tcl.GetVerb() == "says" && tcl.GetSubject().GetEntityType() == "key" {
			if certlib.SameKey(k, tcl.GetSubject().GetKey()) {
				alreadyProved.Proved = append(alreadyProved.Proved, &tcl)
			} else {
				return false
			}
		}
	} else {
		return false
	}
	return true
}

func AddNewFactsForOePlatformAttestation(publicPolicyKey *certprotos.KeyMessage, alreadyProved *certprotos.ProvedStatements) bool {
	return false
}

func AddNewFactsForAbbreviatedPlatformAttestation(publicPolicyKey *certprotos.KeyMessage,
	alreadyProved *certprotos.ProvedStatements) bool {

	// At this point, already proved should contain
	//      "policyKey is-trusted"
	//      "platformKey says attestationKey is-trusted-for-attestation
	//      "attestKey says enclaveKey speaks-for measurement"
	// Add
	//      "policyKey says measurement is-trusted"
	//      "policyKey says platformKey is-trusted-for-attestation"
	// Get platform measurement statement and platform statement
	// Find the corresponding "measurement is-trusted" in measurements
	//      This is signedPolicyKeySaysMeasurementIsTrusted
	//      Add it
	// Find the corresponding "platformKey is-trusted" in platforms 
	//      This is signedPolicyKeySaysPlatformKeyIsTrusted
	//      Add it
	if len(alreadyProved.Proved) != 3 {
		fmt.Printf("AddNewFactsForAbbreviatedPlatformAttestation, Error 1\n")
		return false
	}

	// Get measurement from "attestKey says enclaveKey speaks-for measurement"
	mc := alreadyProved.Proved[2]
	if mc.Subject == nil || mc.Verb == nil || mc.Clause == nil {
		fmt.Printf("AddNewFactsForAbbreviatedPlatformAttestation, bad measurement evidence(1)\n")
		return false
	}
	if mc.Clause.Object == nil {
		fmt.Printf("AddNewFactsForAbbreviatedPlatformAttestation, bad measurement evidence (2)\n")
		return false
	}
	if mc.Clause.Object.GetEntityType() != "measurement" {
		fmt.Printf("AddNewFactsForAbbreviatedPlatformAttestation, bad measurement evidence (3)\n")
		return false
	}
	prog_m := mc.Clause.Object.Measurement

	// Get platformKey from "platformKey says attestationKey is-trusted-for-attestation
	kc := alreadyProved.Proved[1]
	if kc.Subject == nil || kc.Verb == nil || kc.Clause == nil {
		fmt.Printf("AddNewFactsForAbbreviatedPlatformAttestation, bad platform evidence(1)\n")
		return false
	}
	if kc.Subject.GetEntityType() != "key" {
		fmt.Printf("AddNewFactsForAbbreviatedPlatformAttestation, bad platform evidence(2)\n")
		return false
	}
	plat_key := kc.Subject.Key

	signedPolicyKeySaysMeasurementIsTrusted := findPolicyFromMeasurement(prog_m)
	if signedPolicyKeySaysMeasurementIsTrusted == nil {
		fmt.Printf("AddNewFactsForAbbreviatedPlatformAttestation, can't find measurement policy\n")
		return false
	}
	signedPolicyKeySaysPlatformKeyIsTrusted := findPolicyFromKey(plat_key)
	if signedPolicyKeySaysMeasurementIsTrusted == nil {
		fmt.Printf("AddNewFactsForAbbreviatedPlatformAttestation, can't find platform policy\n")
		return false
	}

	// Debug
	fmt.Printf("\nPolicy:\n")
	certlib.PrintSignedClaim(signedPolicyKeySaysMeasurementIsTrusted)
	fmt.Printf("\n")
	certlib.PrintSignedClaim(signedPolicyKeySaysPlatformKeyIsTrusted)
	fmt.Printf("\n")

	if !AddFactFromSignedClaim(signedPolicyKeySaysPlatformKeyIsTrusted, alreadyProved) {
		fmt.Printf("Couldn't AddFactFromSignedClaim, Error 2\n")
		return false
	}

	if !AddFactFromSignedClaim(signedPolicyKeySaysMeasurementIsTrusted, alreadyProved) {
		fmt.Printf("Couldn't AddFactFromSignedClaim, Error 1\n")
		return false
	}

	return true
}

func AddNewFactsForAugmentedPlatformAttestation(publicPolicyKey *certprotos.KeyMessage,
	alreadyProved *certprotos.ProvedStatements) bool {

	// At this point, already proved should contain
	//      "policyKey is-trusted"
	//      "policyKey says attestKey is-trusted-for-attestation"
	//      "attestKey says enclaveKey speaks-for measurement"
	// Add
	//      "policyKey says measurement is-trusted"
	// Get platform measurement statement and platform statement
	// Find the corresponding "measurement is-trusted" in measurements
	//      This is signedPolicyKeySaysMeasurementIsTrusted
	//      Add it
	if len(alreadyProved.Proved) != 3 {
		fmt.Printf("AddNewFactsForAugmentedPlatformAttestation, Error 1\n")
		return false
	}

	// Get measurement from "attestKey says enclaveKey speaks-for measurement"
	mc := alreadyProved.Proved[2]
	if mc.Subject == nil || mc.Verb == nil || mc.Clause == nil {
		fmt.Printf("AddNewFactsForAugmentedPlatformAttestation, bad measurement evidence(1)\n")
		return false
	}
	if mc.Clause.Object == nil {
		fmt.Printf("AddNewFactsForAugmentedPlatformAttestation, bad measurement evidence (2)\n")
		return false
	}
	if mc.Clause.Object.GetEntityType() != "measurement" {
		fmt.Printf("AddNewFactsForAugmentedPlatformAttestation, bad measurement evidence (3)\n")
		return false
	}
	prog_m := mc.Clause.Object.Measurement

	signedPolicyKeySaysMeasurementIsTrusted := findPolicyFromMeasurement(prog_m)
	if signedPolicyKeySaysMeasurementIsTrusted == nil {
		fmt.Printf("AddNewFactsForAugmentedPlatformAttestation, can't find measurement policy\n")
		return false
	}

	// Debug
	fmt.Printf("\nPolicy:\n")
	certlib.PrintSignedClaim(signedPolicyKeySaysMeasurementIsTrusted)
	fmt.Printf("\n")

	if !AddFactFromSignedClaim(signedPolicyKeySaysMeasurementIsTrusted, alreadyProved) {
		fmt.Printf("Couldn't AddFactFromSignedClaim, Error 1\n")
		return false
	}

	return true
}

// Returns toProve and proof steps
func ConstructProofFromOeEvidence(publicPolicyKey *certprotos.KeyMessage, alreadyProved certprotos.ProvedStatements) (*certprotos.VseClause, *certprotos.Proof) {

	// At this point, the evidence should be
	//      "policyKey is-trusted"
	//      "policyKey says platformKey is-trusted-for-attestation"
	//      "enclaveKey speaks-for measurement
	//      "policyKey says measurement is-trusted"

	var toProve *certprotos.VseClause = nil
	proof := &certprotos.Proof{}

	return toProve, proof
}

// Returns toProve and proof steps
func ConstructProofFromFullVseEvidence(publicPolicyKey *certprotos.KeyMessage,
	alreadyProved certprotos.ProvedStatements, purpose string) (*certprotos.VseClause, *certprotos.Proof) {

	// At this point, alreadyProved should be
	//      "policyKey is-trusted"
	//      "platformKey says attestationKey is-trusted-for-attestation"
	//      "attestKey says enclaveKey speaks-for measurement
	//      "policyKey says platformKey is-trusted-for-attestation"
	//      "policyKey says measurement is-trusted"

	// Debug
	fmt.Printf("ConstructProofFromFullVseEvidence entries %d\n", len(alreadyProved.Proved))

	proof := &certprotos.Proof{}
	r1 := int32(1)
	r3 := int32(3)
	r5 := int32(5)
	r6 := int32(6)
	r7 := int32(7)

	policyKeyIsTrusted := alreadyProved.Proved[0]
	policyKeySaysMeasurementIsTrusted := alreadyProved.Proved[4]
	measurementIsTrusted := policyKeySaysMeasurementIsTrusted.Clause
	ps1 := certprotos.ProofStep {
		S1: policyKeyIsTrusted,
		S2: policyKeySaysMeasurementIsTrusted,
		Conclusion: measurementIsTrusted,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps1)

	policyKeySaysPlatformKeyIsTrusted := alreadyProved.Proved[3]
	platformKeyIsTrusted := policyKeySaysPlatformKeyIsTrusted.Clause
	ps2 := certprotos.ProofStep {
		S1: policyKeyIsTrusted,
		S2: policyKeySaysPlatformKeyIsTrusted,
		Conclusion: platformKeyIsTrusted,
		RuleApplied: &r5,
	}
	proof.Steps = append(proof.Steps, &ps2)

	platformKeySaysAttestKeyIsTrusted := alreadyProved.Proved[1]
	attestKeyIsTrusted := platformKeySaysAttestKeyIsTrusted.Clause
	ps3 := certprotos.ProofStep {
		S1: platformKeyIsTrusted,
		S2: platformKeySaysAttestKeyIsTrusted,
		Conclusion: attestKeyIsTrusted,
		RuleApplied: &r5,
	}
	proof.Steps = append(proof.Steps, &ps3)

	attestKeySaysEnclaveKeySpeaksForMeasurement := alreadyProved.Proved[2]
	enclaveKeySpeaksForMeasurement := attestKeySaysEnclaveKeySpeaksForMeasurement.Clause
	ps4 := certprotos.ProofStep {
	S1: attestKeyIsTrusted,
	S2: attestKeySaysEnclaveKeySpeaksForMeasurement,
	Conclusion: enclaveKeySpeaksForMeasurement,
	RuleApplied: &r6,
	}
	proof.Steps = append(proof.Steps, &ps4)

	var toProve *certprotos.VseClause = nil
	isTrustedForAuth := "is-trusted-for-authentication"
	isTrustedForAttest:= "is-trusted-for-attestation"
	if  purpose == "attestation" {
		toProve =  certlib.MakeUnaryVseClause(enclaveKeySpeaksForMeasurement.Subject,
			&isTrustedForAttest)
		ps5 := certprotos.ProofStep {
		S1: measurementIsTrusted,
		S2: enclaveKeySpeaksForMeasurement,
		Conclusion: toProve,
		RuleApplied: &r7,
		}
		proof.Steps = append(proof.Steps, &ps5)
	} else {
		toProve =  certlib.MakeUnaryVseClause(enclaveKeySpeaksForMeasurement.Subject,
			&isTrustedForAuth)
		ps5 := certprotos.ProofStep {
		S1: measurementIsTrusted,
		S2: enclaveKeySpeaksForMeasurement,
		Conclusion: toProve,
		RuleApplied: &r1,
		}
		proof.Steps = append(proof.Steps, &ps5)
	}

	return toProve, proof
}

// Returns toProve and proof steps
func ConstructProofFromShortVseEvidence(publicPolicyKey *certprotos.KeyMessage,
	alreadyProved certprotos.ProvedStatements, purpose string) (*certprotos.VseClause, *certprotos.Proof) {

	// At this point, alreadyProved should be
	//      "policyKey is-trusted"
	//      "platformKey says attestationKey is-trusted-for-attestation"
	//      "attestKey says enclaveKey speaks-for measurement
	//      "policyKey says measurement is-trusted"

	// Debug
	fmt.Printf("ConstructProofFromFullVseEvidence entries %d\n", len(alreadyProved.Proved))

	proof := &certprotos.Proof{}
	r1 := int32(1)
	r3 := int32(3)
	r5 := int32(5)
	r6 := int32(6)
	r7 := int32(7)

	policyKeyIsTrusted := alreadyProved.Proved[0]
	policyKeySaysMeasurementIsTrusted := alreadyProved.Proved[3]
	measurementIsTrusted := policyKeySaysMeasurementIsTrusted.Clause
	ps1 := certprotos.ProofStep {
		S1: policyKeyIsTrusted,
		S2: policyKeySaysMeasurementIsTrusted,
		Conclusion: measurementIsTrusted,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps1)

	policyKeySaysAttestKeyIsTrusted := alreadyProved.Proved[1]
	attestKeyIsTrusted := policyKeySaysAttestKeyIsTrusted.Clause
	ps3 := certprotos.ProofStep {
		S1: policyKeyIsTrusted,
		S2: policyKeySaysAttestKeyIsTrusted,
		Conclusion: attestKeyIsTrusted,
		RuleApplied: &r5,
	}
	proof.Steps = append(proof.Steps, &ps3)

	attestKeySaysEnclaveKeySpeaksForMeasurement := alreadyProved.Proved[2]
	enclaveKeySpeaksForMeasurement := attestKeySaysEnclaveKeySpeaksForMeasurement.Clause
	ps4 := certprotos.ProofStep {
	S1: attestKeyIsTrusted,
	S2: attestKeySaysEnclaveKeySpeaksForMeasurement,
	Conclusion: enclaveKeySpeaksForMeasurement,
	RuleApplied: &r6,
	}
	proof.Steps = append(proof.Steps, &ps4)

	var toProve *certprotos.VseClause = nil
	isTrustedForAuth := "is-trusted-for-authentication"
	isTrustedForAttest:= "is-trusted-for-attestation"
	if  purpose == "attestation" {
		toProve =  certlib.MakeUnaryVseClause(enclaveKeySpeaksForMeasurement.Subject,
			&isTrustedForAttest)
		ps5 := certprotos.ProofStep {
		S1: measurementIsTrusted,
		S2: enclaveKeySpeaksForMeasurement,
		Conclusion: toProve,
		RuleApplied: &r7,
		}
		proof.Steps = append(proof.Steps, &ps5)
	} else {
		toProve =  certlib.MakeUnaryVseClause(enclaveKeySpeaksForMeasurement.Subject,
			&isTrustedForAuth)
		ps5 := certprotos.ProofStep {
		S1: measurementIsTrusted,
		S2: enclaveKeySpeaksForMeasurement,
		Conclusion: toProve,
		RuleApplied: &r1,
		}
		proof.Steps = append(proof.Steps, &ps5)
	}

	return toProve, proof
}

//      ConstructProofFromRequest first checks evidence and make sure each evidence
//	      component is verified and it put in alreadyProved Statements
//      Next, alreadyProved is augmented to include additional true statements
//	      required for the proof
//      Finally a proof is constructed
//
//      Returns the proof goal (toProve), the proof steps (proof), 
//	      and a list of true statements (alreadyProved)
func ConstructProofFromRequest(evidenceType string, support *certprotos.EvidencePackage, purpose string) (*certprotos.VseClause, *certprotos.Proof, *certprotos.ProvedStatements) {

	// Debug
	fmt.Printf("\nConstructProofFromRequest\n")
	fmt.Printf("Submitted evidence type: %s\n", evidenceType)

	if support == nil {
		fmt.Printf("Empty support\n")
		return nil, nil, nil
	}

	if support.ProverType == nil {
		fmt.Printf("No prover type\n")
		return nil, nil, nil
	}

	if support.GetProverType() != "vse-verifier" {
		fmt.Printf("Only vse verifier supported\n")
		return nil, nil, nil
	}

	alreadyProved := &certprotos.ProvedStatements{}
	var toProve *certprotos.VseClause = nil
	var proof *certprotos.Proof = nil

	// Debug
	fmt.Printf("%d fact assertions in evidence\n", len(support.FactAssertion))
	for i := 0; i < len(support.FactAssertion); i++ {
		fmt.Printf("Type: %s\n",  support.FactAssertion[i].GetEvidenceType())
		if support.FactAssertion[i].GetEvidenceType() == "signed-claim" {
			var sc certprotos.SignedClaimMessage
			err := proto.Unmarshal(support.FactAssertion[i].SerializedEvidence, &sc)
			if err != nil {
				fmt.Printf("Can't unmarshal\n");
			} else {
			fmt.Printf("Clause: ")
			vse:= certlib.GetVseFromSignedClaim(&sc)
			certlib.PrintVseClause(vse)
			}
			fmt.Println("")
		} else if support.FactAssertion[i].GetEvidenceType() == "signed-vse-attestation-report" {
			fmt.Printf("Signed report\n")
		} else if support.FactAssertion[i].GetEvidenceType() == "cert" {
			fmt.Printf("Cert evidence type unimplemented\n")
			return nil, nil, nil
		} else {
			fmt.Printf("Invalid evidence type\n")
			return nil, nil, nil
		}
	}

	if !certlib.InitProvedStatements(*publicPolicyKey, support.FactAssertion, alreadyProved) {
		fmt.Printf("certlib.InitProvedStatements failed\n")
		return nil, nil, nil
	}

	// Debug
	fmt.Printf("\nInitial proved statements %d\n", len(alreadyProved.Proved))
	for i := 0; i < len(alreadyProved.Proved); i++ {
		certlib.PrintVseClause(alreadyProved.Proved[i])
		fmt.Println("")
	}
	fmt.Println("")

	// evidenceType should be "full-vse-support", "platform-attestation-only" or
	//      "oe-evidence"
	if evidenceType == "full-vse-support" {
	} else if evidenceType == "platform-attestation-only" {
		if !AddNewFactsForAbbreviatedPlatformAttestation(publicPolicyKey, alreadyProved) {
			fmt.Printf("AddNewFactsForAbbreviatedPlatformAttestation failed\n")
			return nil, nil, nil
		}
	} else if evidenceType == "augmented-platform-attestation-only" {
		if !AddNewFactsForAugmentedPlatformAttestation(publicPolicyKey, alreadyProved) {
			fmt.Printf("AddNewFactsForAugmentedPlatformAttestation failed\n")
			return nil, nil, nil
		}
	} else if evidenceType == "oe-evidence" {
		if !AddNewFactsForOePlatformAttestation(publicPolicyKey, alreadyProved) {
			fmt.Printf("AddNewFactsForOePlatformAttestation failed\n")
			return nil, nil, nil
		}
	} else {
		fmt.Printf("Invalid Evidence type: %s\n", evidenceType)
		return nil, nil, nil
	}

	// Debug
	fmt.Printf("Augmented proved statements %d\n", len(alreadyProved.Proved))
	for i := 0; i < len(alreadyProved.Proved); i++ {
		certlib.PrintVseClause(alreadyProved.Proved[i])
		fmt.Println("")
	}

	if evidenceType == "full-vse-support" || evidenceType == "platform-attestation-only" {
		toProve, proof = ConstructProofFromFullVseEvidence(publicPolicyKey, *alreadyProved, purpose)
		if toProve == nil {
			fmt.Printf("ConstructProofFromFullVseEvidence failed\n")
			return nil, nil, nil
		}
	} else if evidenceType == "augmented-platform-attestation-only" {
		toProve, proof = ConstructProofFromShortVseEvidence(publicPolicyKey, *alreadyProved, purpose)
		if toProve == nil {
			fmt.Printf("ConstructProofFromFullVseEvidence failed\n")
			return nil, nil, nil
		}
	} else if evidenceType == "oe-evidence" {
		toProve, proof = ConstructProofFromOeEvidence(publicPolicyKey, *alreadyProved)
		if toProve == nil {
			fmt.Printf("ConstructProofFromOeEvidence failed\n")
			return nil, nil, nil
		}
	} else {
		return nil, nil, nil
	}

	// Debug
	if toProve != nil {
		fmt.Printf("To prove: ")
		certlib.PrintVseClause(toProve)
	}
	fmt.Printf("\n\nProof:\n")
	for i := 0; i < len(proof.Steps); i++ {
		certlib.PrintProofStep("    ", proof.Steps[i])
	}
	fmt.Println()
	fmt.Println()

	return toProve, proof, alreadyProved
}

func getAppMeasurementFromProvedStatements(appKeyEntity *certprotos.EntityMessage,
		alreadyProved *certprotos.ProvedStatements) []byte {

	for i := 0; i < len(alreadyProved.Proved); i++ {
		if certlib.SameEntity(alreadyProved.Proved[i].GetSubject(), appKeyEntity) {
			if alreadyProved.Proved[i].GetVerb() == "speaks-for" {
				if alreadyProved.Proved[i].Object != nil &&
					alreadyProved.Proved[i].Object.GetEntityType() == "measurement" {
					return alreadyProved.Proved[i].Object.Measurement
				}
			}
		}
	}
	return nil
}

func logRequest(b []byte) *string {
	if b == nil {
		return nil
	}
	s := strconv.Itoa(dataPacketFileNum)
	dataPacketFileNum = dataPacketFileNum + 1
	fileName := *logDir + "/" + "SSReq" + "-" + s
	if ioutil.WriteFile(fileName, b, 0666)  != nil {
		fmt.Printf("Can't write %s\n", fileName)
		return nil
	}
	return &fileName
}

func logResponse(b []byte) *string {
	if b == nil {
		return nil
	}
	s := strconv.Itoa(dataPacketFileNum)
	dataPacketFileNum = dataPacketFileNum + 1
	fileName := *logDir + "/" + "SSRsp" + "-" + s
	if ioutil.WriteFile(fileName, b, 0666)  != nil {
		fmt.Printf("Can't write %s\n", fileName)
		return nil
	}
	return &fileName
}

// Todo: Consider logging the proof and IP address too.
func logEvent(msg string, req []byte, resp []byte) {
	if !logging {
		return
	}
	reqName := logRequest(req)
	respName := logResponse(resp)
	logger.Printf("%s, ", msg)
	if reqName != nil {
		logger.Printf("%s ,", reqName)
	} else {
		logger.Printf("No request,")
	}
	if respName != nil {
		logger.Printf("%s\n", respName)
	} else {
		logger.Printf("No response\n")
	}
}

// Procedure is:
//      read a message
//      evaluate the trust assertion
//      if it succeeds,
//	      sign a cert
//	      save the proof, action and cert info in the transaction files
//	      save net infor for forensics
//      if it fails
//	      save net infor for forensics
//	if logging is enabled, log event, request and response
func serviceThread(conn net.Conn, client string) {

	b := make([]byte, 8192)
	n, err := conn.Read(b)
	if err != nil {
		fmt.Printf("n: %d\n", n)
		logEvent("Can't read request", nil, nil)
		return
	}

	request:= &certprotos.TrustRequestMessage{}
	err = proto.Unmarshal(b[0:n], request)
	if err != nil {
		fmt.Println("serviceThread: Failed to decode request", err)
		logEvent("Can't unmarshal request", nil, nil)
		return
	}

	// Debug
	fmt.Printf("serviceThread: Trust request received:\n")
	certlib.PrintTrustRequest(request)

	// Prepare response
	succeeded := "succeeded"
	failed := "failed"

	response := certprotos.TrustResponseMessage{}
	response.RequestingEnclaveTag = request.RequestingEnclaveTag
	response.ProvidingEnclaveTag = request.ProvidingEnclaveTag
	//response.Artifact = make([]byte, 5)
	response.Status = &failed

	// Construct the proof
	var purpose string
	if  request.Purpose == nil {
		purpose =  "authentication"
	} else {
		purpose =  *request.Purpose
	}
	toProve, proof, alreadyProved := ConstructProofFromRequest(
			request.GetSubmittedEvidenceType(), request.GetSupport(),
                        purpose)
	if toProve == nil || proof == nil || alreadyProved == nil {
		// Debug
		fmt.Printf("Constructing Proof fails\n")
		logEvent("Can't construct proof from request", b[0:n], nil)

		// Debug
		fmt.Printf("Sending response\n")
		certlib.PrintTrustReponse(&response)

		// send response
		rb, err := proto.Marshal(&response)
		if err != nil {
			logEvent("Couldn't marshall request", b[0:n], nil)
			return
		}
		_, err = conn.Write(rb)
		if response.Status != nil && *response.Status == "succeeded" {
			logEvent("Successful request", b[0:n], rb)
		} else {
			logEvent("Failed Request", b[0:n], rb)
		}
			return
	} else {
		// Debug
		fmt.Printf("Constructing Proof succeeded\n")
	}
	appKeyEntity := toProve.GetSubject()

	// Debug
	if toProve != nil {
		fmt.Printf("To prove: ")
		certlib.PrintVseClause(toProve)
		fmt.Printf("\n")
	}

	// Verify proof and send response
	var appOrgName string = "anonymous"
	if  toProve.Subject.Key != nil && toProve.Subject.Key.KeyName != nil {
		appOrgName = *toProve.Subject.Key.KeyName
	}

	// Debug
	fmt.Printf("Verifying proof %d steps\n", len(proof.Steps))

	// Check proof
	if proof == nil {
		response.Status = &failed
	} else if certlib.VerifyProof(publicPolicyKey, toProve, proof, alreadyProved) {
		fmt.Printf("Proof verified\n")
		// Produce Artifact
		if toProve.Subject == nil && toProve.Subject.Key == nil &&
				toProve.Subject.Key.KeyName == nil {
			fmt.Printf("toProve check failed\n")
			certlib.PrintVseClause(toProve)
			fmt.Println()
			response.Status = &failed
		} else {
			if purpose == "attestation" {
				sr := certlib.ProducePlatformRule(&privatePolicyKey, policyCert,
					toProve.Subject.Key, duration)
				if sr == nil {
					response.Status = &succeeded
				} else {
					response.Status = &succeeded
					response.Artifact = sr
				}
			} else {
				// find statement appKey speaks-for measurement in alreadyProved and reset appOrgName
				m := getAppMeasurementFromProvedStatements(appKeyEntity,  alreadyProved)
				if m != nil {
					appOrgName = "Measured-" + hex.EncodeToString(m)
				}
				sn = sn + 1
				org := "CertifierUsers"
				cert := certlib.ProduceAdmissionCert(&privatePolicyKey, policyCert,
					toProve.Subject.Key, org,
					appOrgName, sn, duration)
				if cert == nil {
					fmt.Printf("certlib.ProduceAdmissionCert returned nil\n")
					response.Status = &failed
				} else {
					response.Status = &succeeded
					response.Artifact = cert.Raw
				}
			}
		}
	} else {
		fmt.Printf("Verifying proof failed\n")
		response.Status = &failed
	}

	// Debug
	fmt.Printf("Sending response\n")
	certlib.PrintTrustReponse(&response)

	// send response
	rb, err := proto.Marshal(&response)
	if err != nil {
		logEvent("Couldn't marshall request", b[0:n], nil)
		return
	}
	_, err = conn.Write(rb)
	if response.Status != nil && *response.Status == "succeeded" {
		logEvent("Successful request", b[0:n], rb)
	} else {
		logEvent("Failed Request", b[0:n], rb)
	}
	return
}


func server(serverAddr string, arg string) {

	if initCertifierService() != true {
		fmt.Println("Server: failed to initialize server")
		os.Exit(1)
	}

	var sock net.Listener
	var err error
	var conn net.Conn

	// Listen for clients.
	fmt.Printf("simpleserver: Listening\n")
	sock, err = net.Listen("tcp", serverAddr)
	if err != nil {
		fmt.Printf("simpleserver, listen error: ", err, "\n")
		return
	}

	// Service client connections.
	for {
		fmt.Printf("server: at accept\n")
		conn, err = sock.Accept()
		if err != nil {
			fmt.Printf("simpleserver: can't accept connection: %s\n", err.Error())
			continue
		}
		// Todo: maybe get client name and client IP for logging.
		var clientName string = "blah"
		go serviceThread(conn, clientName)
	}
}

func main() {

	flag.Parse()

	var serverAddr string
	serverAddr = *serverHost + ":" + *serverPort
	var arg string = "something"

	// later this may turn into a TLS connection, we'll see
	server(serverAddr, arg)
	fmt.Printf("simpleserver: done\n")
}
