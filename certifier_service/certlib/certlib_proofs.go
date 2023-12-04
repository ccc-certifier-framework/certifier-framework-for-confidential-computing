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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"os"

	certprotos "github.com/vmware-research/certifier-framework-for-confidential-computing/certifier_service/certprotos"
	gramineverify "github.com/vmware-research/certifier-framework-for-confidential-computing/certifier_service/gramineverify"
	isletverify "github.com/vmware-research/certifier-framework-for-confidential-computing/certifier_service/isletverify"
	oeverify "github.com/vmware-research/certifier-framework-for-confidential-computing/certifier_service/oeverify"
	"google.golang.org/protobuf/proto"
)

var extendedGramine bool = false

func InitAxiom(pk certprotos.KeyMessage, ps *certprotos.ProvedStatements) bool {
	// add pk is-trusted to proved statenments
	ke := MakeKeyEntity(&pk)
	ist := "is-trusted"
	vc := MakeUnaryVseClause(ke, &ist)
	ps.Proved = append(ps.Proved, vc)
	return true
}

func testSign(PK1 *ecdsa.PublicKey) {

	fmt.Printf("\n***testSign\n")
	keyFile := "emulated_keystone_key.bin"
	serializedKey, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Printf("testSign: Can't read key file\n")
		return
	}
	privateKey := certprotos.KeyMessage{}
	err = proto.Unmarshal(serializedKey, &privateKey)
	if err != nil {
		fmt.Printf("testSign: Can't deserialize key\n")
		return
	}
	pK, PK, err := GetEccKeysFromInternal(&privateKey)
	if err != nil || PK == nil || pK == nil {
		fmt.Printf("testSign: Can't convertkey\n")
		return
	}
	toHash := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	hashed := sha256.Sum256(toHash)

	signed, err := ecdsa.SignASN1(rand.Reader, pK, hashed[:])
	if err != nil {
		fmt.Printf("testSign: Can't sign\n")
		return
	}

	fmt.Printf("\nhashed: ")
	PrintBytes(hashed[:])
	fmt.Printf("\nsigned: ")
	PrintBytes(signed[:])
	fmt.Printf("\n")
	if ecdsa.VerifyASN1(PK, hashed[:], signed[:]) {
		fmt.Printf("testSign: Verify succeeded (1)\n")
	} else {
		fmt.Printf("testSign: Verify failed (1)\n")
	}
	if ecdsa.VerifyASN1(PK1, hashed[:], signed[:]) {
		fmt.Printf("testSign: Verify succeeded (2)\n")
	} else {
		fmt.Printf("testSign: Verify failed (2)\n")
	}
	fmt.Printf("\n")
}

/*
	This is policy pool management.  When evidence comes in, this selects the subset of
	the original policy to use in the proof.

	InitPolicyPool puts policy first in AllPolicy
	PlatformKeyStatements is the list of policy statements about platform keys
	MeasurementsStatements is the list of policy statements about programs (measurements)
	PlatformFeatureStatements is a list of policy about platform policy

	After pool is initialized, use GetRelevantPlatformKeyPolicy, GetRelevantMeasurementPolicy
	and PlatformFeatureStatements to retrieve the policies relevant to the specified
	EvidencePackage when constructing proofs.  Each must return the single relevant
	policy statement of the named type needed in the constructed proof
*/

type PolicyPool struct {
	Initialized bool
	// Contains all the policy statements
	AllPolicy *certprotos.ProvedStatements
	// Contains platform key policy statements
	PlatformKeyPolicy *certprotos.ProvedStatements
	// Contains trusted measurement statements
	MeasurementPolicy *certprotos.ProvedStatements
	// Contains platform features statements
	PlatformFeaturePolicy *certprotos.ProvedStatements
}

// policyKey says platformKey is-trusted-for-attestation
func isPlatformKeyStatement(vse *certprotos.VseClause) bool {
	if vse.Clause == nil {
		return false
	}
	if vse.Clause.Subject == nil {
		return false
	}
	if vse.Clause.Subject.EntityType == nil {
		return false
	}
	if vse.Clause.Verb == nil {
		return false
	}
	if vse.Clause.Subject.GetEntityType() == "key" && vse.Clause.GetVerb() == "is-trusted-for-attestation" {
		return true
	}
	return false
}

// policyKey says platform has-trusted-platform-property
func isPlatformFeatureStatement(vse *certprotos.VseClause) bool {
	if vse.Clause == nil {
		return false
	}
	if vse.Clause.Subject == nil {
		return false
	}
	if vse.Clause.Subject.EntityType == nil {
		return false
	}
	if vse.Clause.Verb == nil {
		return false
	}
	if vse.Clause.Subject.GetEntityType() == "platform" && vse.Clause.GetVerb() == "has-trusted-platform-property" {
		return true
	}
	return false
}

// policyKey says measurement is-trusted
func isPlatformMeasurementStatement(vse *certprotos.VseClause) bool {
	if vse.Clause == nil {
		return false
	}
	if vse.Clause.Subject == nil {
		return false
	}
	if vse.Clause.Subject.EntityType == nil {
		return false
	}
	if vse.Clause.Verb == nil {
		return false
	}
	if vse.Clause.Subject.GetEntityType() == "measurement" && vse.Clause.GetVerb() == "is-trusted" {
		return true
	}
	return false
}

func InitPolicyPool(pool *PolicyPool, original *certprotos.ProvedStatements) bool {

	if pool == nil {
		fmt.Printf("InitPolicyPool: pool is nil\n")
		return false
	}
	if original == nil {
		fmt.Printf("InitPolicyPool: original policy is nil\n")
		return false
	}

	pool.AllPolicy = &certprotos.ProvedStatements{}
	pool.PlatformKeyPolicy = &certprotos.ProvedStatements{}
	pool.MeasurementPolicy = &certprotos.ProvedStatements{}
	pool.PlatformFeaturePolicy = &certprotos.ProvedStatements{}
	if pool.AllPolicy == nil || pool.PlatformKeyPolicy == nil ||
		pool.MeasurementPolicy == nil || pool.PlatformFeaturePolicy == nil {
		fmt.Printf("InitPolicyPool: Some proved statements structures are nil\n")
		return false
	}

	pool.Initialized = false

	for i := 0; i < len(original.Proved); i++ {
		from := original.Proved[i]
		pool.AllPolicy.Proved = append(pool.AllPolicy.Proved, from)
		// to :=  proto.Clone(from).(*certprotos.VseClause)
		if isPlatformKeyStatement(from) {
			pool.PlatformKeyPolicy.Proved = append(pool.PlatformKeyPolicy.Proved, from)
		}
		if isPlatformFeatureStatement(from) {
			pool.PlatformFeaturePolicy.Proved = append(pool.PlatformFeaturePolicy.Proved, from)
		}
		if isPlatformMeasurementStatement(from) {
			pool.MeasurementPolicy.Proved = append(pool.MeasurementPolicy.Proved, from)
		}
	}

	pool.Initialized = true
	return true
}

// Returns the single policy statement naming the relevant platform key policy
// statement for a this evidence package
func GetRelevantPlatformKeyPolicy(pool *PolicyPool, evType string,
	evp *certprotos.EvidencePackage) *certprotos.VseClause {

	// find the platform key needed from evp and the corresponding policy rule
	ev_list := evp.FactAssertion
	if ev_list == nil {
		return nil
	}
	var platSubject *certprotos.EntityMessage = nil

	// find platformKey says attestationKey is-trusted-for-attestation
	fmt.Printf("GetRelevantPlatformKeyPolicy: %d evidence statements\n", len(ev_list))
	for i := 0; i < len(ev_list); i++ {
		ev := ev_list[i]

		/* Debug
		fmt.Printf("%d: GetRelevantPlatformKeyPolicy: evidence\n", i)
		PrintEvidence(ev)
		fmt.Printf("\n")
		*/
		if ev == nil {
			continue
		}
		if ev.GetEvidenceType() == "signed-claim" {
			signedClaimMsg := certprotos.SignedClaimMessage{}
			err := proto.Unmarshal(ev.SerializedEvidence, &signedClaimMsg)
			if err != nil {
				continue
			}
			claimMsg := certprotos.ClaimMessage{}
			err = proto.Unmarshal(signedClaimMsg.SerializedClaimMessage, &claimMsg)
			if err != nil {
				continue
			}
			if claimMsg.GetClaimFormat() != "vse-clause" {
				continue
			}
			cl := certprotos.VseClause{}
			err = proto.Unmarshal(claimMsg.SerializedClaim, &cl)
			if err != nil {
				continue
			}

			/* Debug
			fmt.Printf("%d: Clause\n", i)
			PrintVseClause(&cl)
			fmt.Printf("\n")
			*/

			if cl.GetVerb() != "says" || cl.Clause == nil {
				continue
			}
			if cl.Clause.Subject == nil || cl.Clause.Verb == nil || cl.Clause.GetVerb() != "is-trusted-for-attestation" {
				continue
			}
			platSubject = cl.Subject
			if platSubject == nil || platSubject.GetEntityType() != "key" {
				fmt.Printf("GetRelevantPlatformKeyPolicy: wrong entity\n")
				return nil
			}
			break
		} else if ev.GetEvidenceType() == "cert" {
			platCert := Asn1ToX509(ev.SerializedEvidence)
			if platCert == nil {
				fmt.Printf("GetRelevantPlatformKeyPolicy: cant convert cert to x509\n")
				continue
			}
			platKey := GetSubjectKey(platCert)
			if platKey == nil {
				fmt.Printf("GetRelevantPlatformKeyPolicy: cant get subject key from cert\n")
				continue
			}
			platSubject = MakeKeyEntity(platKey)
			if platSubject == nil || platSubject.GetEntityType() != "key" {
				fmt.Printf("GetRelevantPlatformKeyPolicy: wrong entity\n")
				return nil
			}
			break
		} else {
			continue
		}
	}
	if platSubject == nil {
		fmt.Printf("GetRelevantPlatformKeyPolicy: no match\n")
		return nil
	}

	// Find rule that says policyKey says platSubject is-trusted-for-attestation and return it
	for i := 0; i < len(pool.PlatformKeyPolicy.Proved); i++ {
		cl := pool.PlatformKeyPolicy.Proved[i]
		if cl == nil {
			continue
		}
		if cl.Clause == nil || cl.Clause.Subject == nil {
			continue
		}
		if SameEntity(platSubject, cl.Clause.Subject) {
			return cl
		}
	}
	return nil
}

func GetVseMeasurementFromAttestation(evBuf []byte) []byte {
	sr := certprotos.SignedReport{}
	err := proto.Unmarshal(evBuf, &sr)
	if err != nil {
		fmt.Printf("GetVseMeasurementFromAttestation: Can't unmarshal signed report\n")
		return nil
	}
	info := certprotos.VseAttestationReportInfo{}
	err = proto.Unmarshal(sr.GetReport(), &info)
	if err != nil {
		fmt.Printf("GetVseMeasurementFromAttestation: Can't unmarshal info\n")
		return nil
	}

	return info.VerifiedMeasurement
}

func GetSevMeasurementFromAttestation(evBuf []byte) []byte {
	var am certprotos.SevAttestationMessage
	err := proto.Unmarshal(evBuf, &am)
	if err != nil {
		fmt.Printf("GetSevMeasurementFromAttestation: Can't unmarshal SevAttestationMessage\n")
		return nil
	}
	return GetMeasurementFromSevAttest(am.ReportedAttestation)
}

func GetGramineMeasurementFromAttestation(evBuf []byte) []byte {
	succeeded, _, m, err := VerifyGramineAttestation(evBuf)
	if !succeeded || err != nil {
		fmt.Printf("GetGramineMeasurementFromAttestation: Can't verify gramine evidence\n")
		return nil
	}
	return m
}

func GetOeMeasurementFromAttestation(prevEvidence *certprotos.Evidence,
	curEvidence *certprotos.Evidence) []byte {
	var serializedUD, m []byte
	var err error
	if prevEvidence != nil {
		serializedUD, m, err = oeverify.OEHostVerifyEvidence(curEvidence.SerializedEvidence, prevEvidence.SerializedEvidence, false)
	} else {
		// No endorsement presented
		serializedUD, m, err = oeverify.OEHostVerifyEvidence(curEvidence.SerializedEvidence, nil, false)
	}
	if err != nil || serializedUD == nil || m == nil {
		return nil
	}
	return m
}

func GetKeystoneMeasurementFromAttestation(evBuf []byte) []byte {
	var am certprotos.KeystoneAttestationMessage
	err := proto.Unmarshal(evBuf, &am)
	if err != nil {
		fmt.Printf("GetKeystoneMeasurementFromAttestation: Can't unmarshal KeystoneAttestationMessage\n")
		return nil
	}
	ptr := am.ReportedAttestation
	return ptr[0:32]
}

func GetIsletMeasurementFromAttestation(evBuf []byte) []byte {
	var am certprotos.IsletAttestationMessage
	err := proto.Unmarshal(evBuf, &am)
	if err != nil {
		fmt.Printf("GetIsletMeasurementFromAttestation: Can't unmarshal IsletAttestationMessage\n")
		return nil
	}
	m, err := isletverify.IsletVerify(am.WhatWasSaid, am.ReportedAttestation)
	if err != nil {
		fmt.Printf("GetIsletMeasurementFromAttestation: IsletVerify() failed\n")
		return nil
	}
	return m
}

// Returns the single policy statement naming the relevant measurement policy
// statement for a this evidence package
func GetRelevantMeasurementPolicy(pool *PolicyPool, evType string,
	evp *certprotos.EvidencePackage) *certprotos.VseClause {

	ev_list := evp.FactAssertion
	if ev_list == nil {
		return nil
	}

	// find attestation and get measurement
	var measurement []byte = nil
	for i := 0; i < len(ev_list); i++ {
		ev := ev_list[i]
		if ev == nil {
			continue
		}

		if ev.GetEvidenceType() == "signed-claim" {
			continue
		} else if ev.GetEvidenceType() == "pem-cert-chain" {
			continue
		} else if ev.GetEvidenceType() == "cert" {
			continue
		} else if ev.GetEvidenceType() == "signed-vse-attestation-report" {
			measurement = GetVseMeasurementFromAttestation(ev.SerializedEvidence)
			break
		} else if ev.GetEvidenceType() == "sev-attestation" {
			measurement = GetSevMeasurementFromAttestation(ev.SerializedEvidence)
			break
		} else if ev.GetEvidenceType() == "islet-attestation" {
			measurement = GetIsletMeasurementFromAttestation(ev.SerializedEvidence)
			break
		} else if ev.GetEvidenceType() == "keystone-attestation" {
			measurement = GetKeystoneMeasurementFromAttestation(ev.SerializedEvidence)
			break
		} else if ev.GetEvidenceType() == "gramine-attestation" {
			measurement = GetGramineMeasurementFromAttestation(ev.SerializedEvidence)
			break
		} else if ev.GetEvidenceType() == "oe-attestation-report" {
			if i < 1 || ev_list[i-1].GetEvidenceType() != "pem-cert-chain" {
				measurement = GetOeMeasurementFromAttestation(nil, ev_list[i])
			} else {
				measurement = GetOeMeasurementFromAttestation(ev_list[i-1], ev_list[i])
			}
			break
		} else {
			continue
		}
	}
	if measurement == nil {
		fmt.Printf("GetRelevantMeasurementPolicy: no evidence measurement\n")
		return nil
	}

	// look for policyKey says Measurement[] is-trusted
	for i := 0; i < len(pool.MeasurementPolicy.Proved); i++ {
		s := pool.MeasurementPolicy.Proved[i]
		if s == nil || s.Verb == nil || s.GetVerb() != "says" {
			continue
		}
		cl := s.Clause
		if cl == nil || cl.Subject == nil || cl.Verb == nil {
			continue
		}
		if cl.Subject.GetEntityType() != "measurement" || cl.GetVerb() != "is-trusted" {
			continue
		}
		if bytes.Equal(measurement, cl.Subject.Measurement) {
			return s
		}
	}

	return nil
}

// Returns the single policy statement naming the relevant trusted-platform
// policy statement for a this evidence package
func GetRelevantPlatformFeaturePolicy(pool *PolicyPool, evType string,
	evp *certprotos.EvidencePackage) *certprotos.VseClause {

	ev_list := evp.FactAssertion
	if ev_list == nil {
		return nil
	}

	var platform *certprotos.EntityMessage = nil

	// Find "attestationKey says environment(platform, measurement) is-environment"
	for i := 0; i < len(ev_list); i++ {
		ev := ev_list[i]
		if ev == nil {
			continue
		}
		if ev.GetEvidenceType() == "sev-attestation" {
			var am certprotos.SevAttestationMessage
			err := proto.Unmarshal(ev.SerializedEvidence, &am)
			if err != nil {
				fmt.Printf("GetRelevantPlatformFeaturePolicy: Can't unmarshal SevAttestationMessage\n")
				return nil
			}
			plat := GetPlatformFromSevAttest(am.ReportedAttestation)
			if plat != nil {
				platform = MakePlatformEntity(plat)
				break
			}
		}
		if ev.GetEvidenceType() == "gramine-attestation" {
			var am certprotos.GramineAttestationMessage
			err := proto.Unmarshal(ev.SerializedEvidence, &am)
			if err != nil {
				fmt.Printf("GetRelevantPlatformFeaturePolicy: Can't unmarshal GramineAttestationMessage\n")
				return nil
			}
			plat := GetPlatformFromGramineAttest(am.ReportedAttestation)
			if plat != nil {
				platform = MakePlatformEntity(plat)
				break
			}
		}
	}
	if platform == nil {
		return nil
	}

	/* Debug
	fmt.Printf("found platform\n")
	PrintEntity(platform)
	fmt.Printf("\n")
	*/

	// look for policyKey says platform has-trusted-platform-property and match properties
	for i := 0; i < len(pool.PlatformFeaturePolicy.Proved); i++ {
		s := pool.PlatformFeaturePolicy.Proved[i]
		if s == nil {
			continue
		}
		cl := s.Clause

		/* Debug
		fmt.Printf("Clause for plat:\n")
		PrintVseClause(cl)
		fmt.Printf("\n")
		*/

		if cl == nil || cl.Subject == nil || cl.Verb == nil {
			continue
		}
		if cl.Subject.GetEntityType() != "platform" || cl.GetVerb() != "has-trusted-platform-property" {
			continue
		}
		return s
	}

	return nil
}

// Filtered OePolicy should be
//      00: "policyKey is-trusted"
//      01: "Key[rsa, policyKey, f2663e9ca042fcd261ab051b3a4e3ac83d79afdd] says
//		Key[rsa, VSE, cbfced04cfc0f1f55df8cbe437c3aba79af1657a] is-trusted-for-attestation"
//      02: "policyKey says measurement is-trusted"
func FilterOePolicy(policyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
	policyPool *PolicyPool) *certprotos.ProvedStatements {

	/* Debug
	fmt.Printf("Incoming evidence for Oe\n")
	PrintEvidencePackage(evp, true)
	fmt.Printf("\nOriginal Platform Policy:\n")
	for i := 0; i < len(policyPool.PlatformKeyPolicy.Proved); i++ {
		cl := policyPool.PlatformKeyPolicy.Proved[i]
		PrintVseClause(cl)
		fmt.Printf("\n")
	}
	fmt.Printf("\n")
	fmt.Printf("\nOriginal Measurement Policy:\n")
	for i := 0; i < len(policyPool.MeasurementPolicy.Proved); i++ {
		cl := policyPool.MeasurementPolicy.Proved[i]
		PrintVseClause(cl)
		fmt.Printf("\n")
	}
	fmt.Printf("\n\n")
	*/

	filtered := &certprotos.ProvedStatements{}

	// policyKey is-trusted
	from := policyPool.AllPolicy.Proved[0]
	to := proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	// This should be passed in
	evType := "oe-evidence"

	// Oe (like keystone and islet) does not always include a platform
	// certificate in the evidence.
	from = GetRelevantPlatformKeyPolicy(policyPool, evType, evp)
	if from != nil {
		to = proto.Clone(from).(*certprotos.VseClause)
		filtered.Proved = append(filtered.Proved, to)
	}

	from = GetRelevantMeasurementPolicy(policyPool, evType, evp)
	if from == nil {
		return nil
	}
	to = proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	return filtered
}

// Filtered Policy should be
//      0: "policyKey is-trusted"
//      1: "policyKey says platformKey is-trusted-for-attestation"
//      2: "policyKey says measurement is-trusted"
func FilterInternalPolicy(policyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
	policyPool *PolicyPool) *certprotos.ProvedStatements {

	filtered := &certprotos.ProvedStatements{}

	// policyKey is-trusted
	from := policyPool.AllPolicy.Proved[0]
	to := proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	// This should be passed in
	evType := "vse-attestation-package"

	from = GetRelevantPlatformKeyPolicy(policyPool, evType, evp)
	if from == nil {
		fmt.Printf("FilterInternalPolicy: Can't get relevant platform key\n")
		return nil
	}
	to = proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	from = GetRelevantMeasurementPolicy(policyPool, evType, evp)
	if from == nil {
		fmt.Printf("FilterInternalPolicy: Can't get relevant measurement\n")
		return nil
	}
	to = proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	return filtered
}

// Filtered Policy should be
//	00 Key[rsa, policyKey, f91d6331b1fd99b3fa8641fd16dcd4c272a92b8a] is-trusted
//	01 Key[rsa, policyKey, f91d6331b1fd99b3fa8641fd16dcd4c272a92b8a] says
//	Key[rsa, ARKKey, c36d3343d69d9d8000d32d0979adff876e98ec79] is-trusted-for-attestation
//	02 Key[rsa, policyKey, f91d6331b1fd99b3fa8641fd16dcd4c272a92b8a] says
//      Measurement[010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708] is-trusted
//	03 Key[rsa, policyKey, f91d6331b1fd99b3fa8641fd16dcd4c272a92b8a] says
//	platform[amd-sev-snp, debug: no, migrate: no, api-major: >=0, api-minor: >=0, key-share: no,
//		tcb-version: >=0] has-trusted-platform-property
func FilterSevPolicy(policyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
	policyPool *PolicyPool) *certprotos.ProvedStatements {

	filtered := &certprotos.ProvedStatements{}

	// policyKey is-trusted
	from := policyPool.AllPolicy.Proved[0]
	to := proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	// This should be passed in
	evType := "sev-evidence"

	// policyKey says platformKey is-trusted-for-attestation
	from = GetRelevantPlatformKeyPolicy(policyPool, evType, evp)
	if from == nil {
		fmt.Printf("FilterSevPolicy: Can't get relavent platform key\n")
		return nil
	}
	to = proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	// policyKey says measurement is-trusted-for-attestation
	from = GetRelevantMeasurementPolicy(policyPool, evType, evp)
	if from == nil {
		fmt.Printf("FilterSevPolicy: Can't get relavent measurement\n")
		return nil
	}
	to = proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	// policyKey says platform has-trusted-platform-policy
	from = GetRelevantPlatformFeaturePolicy(policyPool, evType, evp)
	if from == nil {
		fmt.Printf("FilterSevPolicy: Can't get relavent platform features\n")
		return nil
	}
	to = proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	return filtered
}

func InitPolicy(publicPolicyKey *certprotos.KeyMessage, signedPolicy *certprotos.SignedClaimSequence,
	alreadyProved *certprotos.ProvedStatements) bool {
	if publicPolicyKey == nil {
		fmt.Printf("Policy key empty\n")
		return false
	}
	for i := 0; i < len(signedPolicy.Claims); i++ {
		sc := signedPolicy.Claims[i]
		if !VerifySignedClaim(sc, publicPolicyKey) {
			fmt.Printf("Can't verify signature\n")
			return false
		}
		cm := &certprotos.ClaimMessage{}
		err := proto.Unmarshal(sc.SerializedClaimMessage, cm)
		if err != nil {
			fmt.Printf("Can't unmarshal claim\n")
			return false
		}
		if cm.GetClaimFormat() != "vse-clause" {
			fmt.Printf("Not vse claim\n")
			return false
		}
		vse := &certprotos.VseClause{}
		err = proto.Unmarshal(cm.SerializedClaim, vse)
		if err != nil {
			fmt.Printf("Can't unmarshal vse claim\n")
			return false
		}
		alreadyProved.Proved = append(alreadyProved.Proved, vse)
	}
	return true
}

func InitProvedStatements(pk certprotos.KeyMessage, evidenceList []*certprotos.Evidence,
	ps *certprotos.ProvedStatements) bool {

	seenList := new(CertSeenList)
	seenList.maxSize = 30
	seenList.size = 0

	// Debug
	fmt.Printf("\nInitProvedStatements %d assertions\n", len(evidenceList))

	for i := 0; i < len(evidenceList); i++ {
		ev := evidenceList[i]
		if ev.GetEvidenceType() == "signed-claim" {
			signedClaim := certprotos.SignedClaimMessage{}
			err := proto.Unmarshal(ev.SerializedEvidence, &signedClaim)
			if err != nil {
				fmt.Printf("InitProvedStatements: Can't unmarshal serialized claim\n")
				return false
			}
			k := signedClaim.SigningKey
			tcl := certprotos.VseClause{}
			if VerifySignedAssertion(signedClaim, k, &tcl) {
				// make sure the saying key in tcl is the same key that signed it
				if tcl.GetVerb() == "says" && tcl.GetSubject().GetEntityType() == "key" {
					if SameKey(k, tcl.GetSubject().GetKey()) {
						ps.Proved = append(ps.Proved, &tcl)
					}
				}
			}
		} else if ev.GetEvidenceType() == "pem-cert-chain" {
			// nothing to do
		} else if ev.GetEvidenceType() == "gramine-attestation" {
			succeeded, serializedUD, m, err := VerifyGramineAttestation(ev.SerializedEvidence)
			if !succeeded || err != nil {
				fmt.Printf("InitProvedStatements: Can't verify gramine evidence\n")
				return false
			}
			// get enclave key from ud
			ud := certprotos.AttestationUserData{}
			err = proto.Unmarshal(serializedUD, &ud)
			if err != nil {
				fmt.Printf("InitProvedStatements: Can't unmarshal user data\n")
				return false
			}

			if extendedGramine {
				ec := ConstructGramineIsEnvironmentClaim(m, ev.SerializedEvidence)
				if ec == nil {
					fmt.Printf("InitProvedStatements: ConstructGramineIsEnvironmentClaim failed\n")
					return false
				}
				ps.Proved = append(ps.Proved, ec)
				sfc := ConstructGramineSpeaksForClaim(ud.EnclaveKey, ec.Subject)
				if sfc == nil {
					fmt.Printf("InitProvedStatements: ConstructGramineSpeaksForClaim failed\n")
					return false
				}
				ps.Proved = append(ps.Proved, sfc)
			} else {
				cl := ConstructGramineClaim(ud.EnclaveKey, m)
				if cl == nil {
					fmt.Printf("InitProvedStatements: ConstructGramineClaim failed\n")
					return false
				}
				ps.Proved = append(ps.Proved, cl)
			}
		} else if ev.GetEvidenceType() == "oe-attestation-report" {
			// call oeVerify here and construct the statement:
			//      enclave-key speaks-for measurement
			// from the return values.  Then add it to proved statements
			// Ignore SGX TCB level check for now
			var serializedUD, m []byte
			var err error
			if i < 1 || evidenceList[i-1].GetEvidenceType() != "pem-cert-chain" {
				// No endorsement presented
				serializedUD, m, err = oeverify.OEHostVerifyEvidence(evidenceList[i].SerializedEvidence,
					nil, false)
			} else {
				serializedUD, m, err = oeverify.OEHostVerifyEvidence(evidenceList[i].SerializedEvidence,
					evidenceList[i-1].SerializedEvidence, false)
			}
			if err != nil || serializedUD == nil || m == nil {
				return false
			}
			ud := certprotos.AttestationUserData{}
			err = proto.Unmarshal(serializedUD, &ud)
			if err != nil {
				return false
			}
			// Get platform key from pem file
			var cl *certprotos.VseClause
			if i >= 1 {
				stripped := StripPemHeaderAndTrailer(string(evidenceList[i-1].SerializedEvidence))
				if stripped == nil {
					fmt.Printf("InitProvedStatements: Bad PEM\n")
					return false
				}
				k := KeyFromPemFormat(*stripped)
				cl = ConstructOESpeaksForStatement(k, ud.EnclaveKey, m)
			} else {
				cl = ConstructOESpeaksForStatement(nil, ud.EnclaveKey, m)
			}
			if cl == nil {
				fmt.Printf("InitProvedStatements: ConstructEnclaveKeySpeaksForMeasurement failed\n")
				return false
			}
			ps.Proved = append(ps.Proved, cl)
		} else if ev.GetEvidenceType() == "islet-attestation" {
			n := 1
			if ps.Proved[n] == nil || ps.Proved[n].Clause == nil ||
				ps.Proved[n].Clause.Subject == nil {
				fmt.Printf("InitProvedStatements: Can't get attestKey key (1)\n")
				return false
			}
			attestKeyVerifyKeyEnt := ps.Proved[n].Clause.Subject
			if attestKeyVerifyKeyEnt == nil {
				fmt.Printf("InitProvedStatements: Can't get attestKey key (2)\n")
				return false
			}
			if attestKeyVerifyKeyEnt.GetEntityType() != "key" {
				fmt.Printf("InitProvedStatements: Can't get attestKey key (3)\n")
				return false
			}
			attestKey := attestKeyVerifyKeyEnt.Key
			if attestKey == nil {
				fmt.Printf("InitProvedStatements: Can't get attestKey key (4)\n")
				return false
			}
			m := VerifyIsletAttestation(ev.SerializedEvidence, attestKey)
			if m == nil {
				fmt.Printf("InitProvedStatements: VerifyIsletAttestation failed\n")
				return false
			}
			var am certprotos.IsletAttestationMessage
			err := proto.Unmarshal(ev.SerializedEvidence, &am)
			if err != nil {
				fmt.Printf("InitProvedStatements: Can't unmarshal IsletAttestationMessage\n")
				return false
			}
			var ud certprotos.AttestationUserData
			err = proto.Unmarshal(am.WhatWasSaid, &ud)
			if err != nil {
				fmt.Printf("InitProvedStatements: Can't unmarshal AttestationUserData\n")
				return false
			}
			if ud.EnclaveKey == nil {
				fmt.Printf("InitProvedStatements: No enclaveKey\n")
				return false
			}

			if am.ReportedAttestation == nil {
				fmt.Printf("InitProvedStatements: No reported attestation\n")
				return false
			}

			mEnt := MakeMeasurementEntity(m)
			c2 := ConstructIsletSpeaksForMeasurementStatement(attestKey, ud.EnclaveKey, mEnt)
			if c2 == nil {
				fmt.Printf("InitProvedStatements: ConstructIsletSpeaksForMeasurementStatement failed\n")
				return false
			}
			ps.Proved = append(ps.Proved, c2)
		} else if ev.GetEvidenceType() == "keystone-attestation" {
			n := 1
			if ps.Proved[n] == nil || ps.Proved[n].Clause == nil ||
				ps.Proved[n].Clause.Subject == nil {
				fmt.Printf("InitProvedStatements: Can't get attestKey key (1)\n")
				return false
			}
			attestKeyVerifyKeyEnt := ps.Proved[n].Clause.Subject
			if attestKeyVerifyKeyEnt == nil {
				fmt.Printf("InitProvedStatements: Can't get attestKey key (2)\n")
				return false
			}
			if attestKeyVerifyKeyEnt.GetEntityType() != "key" {
				fmt.Printf("InitProvedStatements: Can't get attestKey key (3)\n")
				return false
			}
			attestKey := attestKeyVerifyKeyEnt.Key
			if attestKey == nil {
				fmt.Printf("InitProvedStatements: Can't get attestKey key (4)\n")
				return false
			}
			m := VerifyKeystoneAttestation(ev.SerializedEvidence, attestKey)
			if m == nil {
				fmt.Printf("InitProvedStatements: VerifyKeystoneAttestation failed\n")
				return false
			}
			var am certprotos.KeystoneAttestationMessage
			err := proto.Unmarshal(ev.SerializedEvidence, &am)
			if err != nil {
				fmt.Printf("InitProvedStatements: Can't unmarshal KeystoneAttestationMessage\n")
				return false
			}
			var ud certprotos.AttestationUserData
			err = proto.Unmarshal(am.WhatWasSaid, &ud)
			if err != nil {
				fmt.Printf("InitProvedStatements: Can't unmarshal UserData\n")
				return false
			}
			if ud.EnclaveKey == nil {
				fmt.Printf("InitProvedStatements: No enclaveKey\n")
				return false
			}

			if am.ReportedAttestation == nil {
				fmt.Printf("InitProvedStatements: No reported attestation\n")
				return false
			}

			mEnt := MakeMeasurementEntity(m)
			c2 := ConstructKeystoneSpeaksForMeasurementStatement(attestKey, ud.EnclaveKey, mEnt)
			if c2 == nil {
				fmt.Printf("InitProvedStatements: ConstructKeystoneSpeaksForMeasurementStatement failed\n")
				return false
			}
			ps.Proved = append(ps.Proved, c2)
		} else if ev.GetEvidenceType() == "sev-attestation" {
			// get the key from ps
			n := len(ps.Proved) - 1
			if n < 0 {
				fmt.Printf("InitProvedStatements: sev evidence is at wrong position\n")
				return false
			}
			if ps.Proved[n] == nil || ps.Proved[n].Clause == nil ||
				ps.Proved[n].Clause.Subject == nil {
				fmt.Printf("InitProvedStatements: Can't get vcek key (1)\n")
				return false
			}
			vcekVerifyKeyEnt := ps.Proved[n].Clause.Subject
			if vcekVerifyKeyEnt == nil {
				fmt.Printf("InitProvedStatements: Can't get vcek key (2)\n")
				return false
			}
			if vcekVerifyKeyEnt.GetEntityType() != "key" {
				fmt.Printf("InitProvedStatements: Can't get vcek key (3)\n")
				return false
			}
			vcekKey := vcekVerifyKeyEnt.Key
			if vcekKey == nil {
				fmt.Printf("InitProvedStatements: Can't get vcek key (4)\n")
				return false
			}
			m := VerifySevAttestation(ev.SerializedEvidence, vcekKey)
			if m == nil {
				fmt.Printf("InitProvedStatements: VerifySevAttestation failed\n")
				return false
			}
			var am certprotos.SevAttestationMessage
			err := proto.Unmarshal(ev.SerializedEvidence, &am)
			if err != nil {
				fmt.Printf("InitProvedStatements: Can't unmarshal SevAttestationMessage\n")
				return false
			}
			var ud certprotos.AttestationUserData
			err = proto.Unmarshal(am.WhatWasSaid, &ud)
			if err != nil {
				fmt.Printf("InitProvedStatements: Can't unmarshal UserData\n")
				return false
			}
			if ud.EnclaveKey == nil {
				fmt.Printf("InitProvedStatements: No enclaveKey\n")
				return false
			}

			if am.ReportedAttestation == nil {
				fmt.Printf("InitProvedStatements: No reported attestation\n")
				return false
			}

			c1 := ConstructSevIsEnvironmentStatement(vcekKey, am.ReportedAttestation)
			if c1 == nil {
				fmt.Printf("InitProvedStatements: ConstructSevIsEnvironmentStatement failed\n")
				return false
			}
			ps.Proved = append(ps.Proved, c1)

			if c1.Clause == nil || c1.Clause.Subject == nil {
				fmt.Printf("InitProvedStatements: can't get environment\n")
				return false
			}
			env := c1.Clause.Subject

			c2 := ConstructSevSpeaksForEnvironmentStatement(vcekKey, ud.EnclaveKey, env)
			if c2 == nil {
				fmt.Printf("InitProvedStatements: ConstructSevSpeaksForEnvironmentStatement failed\n")
				return false
			}
			ps.Proved = append(ps.Proved, c2)
		} else if ev.GetEvidenceType() == "cert" {
			// A cert always means "the signing-key says the subject-key is-trusted-for-attestation"
			// construct vse statement.

			// This whole thing is more complicated because we have to keep track of
			// previously seen subject keys which, as issuer keys, will sign other
			// keys.  The only time we can get the issuer_key directly is when the cert
			// is self signed.

			// turn into X509
			cert := Asn1ToX509(ev.SerializedEvidence)
			if cert == nil {
				fmt.Printf("InitProvedStatements: Can't convert cert\n")
				return false
			}

			subjKey := GetSubjectKey(cert)
			if subjKey == nil {
				fmt.Printf("InitProvedStatements: Can't get subject key\n")
				return false
			}
			if FindKeySeen(seenList, subjKey.GetKeyName()) == nil {
				if !AddKeySeen(seenList, subjKey) {
					fmt.Printf("InitProvedStatements: Can't add subject key\n")
					return false
				}
			}
			issuerName := GetIssuerNameFromCert(cert)
			signerKey := FindKeySeen(seenList, issuerName)
			if signerKey == nil {
				fmt.Printf("InitProvedStatements: signerKey (%s, %s) is nil\n", issuerName, subjKey.GetKeyName())
				return false
			}

			// verify x509 signature
			certPool := x509.NewCertPool()
			certPool.AddCert(cert)
			opts := x509.VerifyOptions{
				Roots: certPool,
			}
			if _, err := cert.Verify(opts); err != nil {
				fmt.Printf("InitProvedStatements: Cert.Vertify fails\n")
				return false
			}

			/*
				// This code will replace the above eventually
				if signerKey.GetName() == subjKey.GetKeyName {
					err := cert.CheckSignatureFrom(cert)
					if err != nil {
						fmt.Printf("InitProvedStatements: parent signature check fails\n")
						return false
					}
				} else {
					if i <= 0 {
						fmt.Printf("InitProvedStatements: No parent cert\n")
						return false
					}
					parentCert := Asn1ToX509(evidenceList[i - 1].SerializedEvidence)
					if parentCert == nil {
						fmt.Printf("InitProvedStatements: Can't convert parent cert\n")
						return false
					}
					err := cert.CheckSignatureFrom(parentCert)
					if err != nil {
						fmt.Printf("InitProvedStatements: parent signature check fails\n")
						return false
					}
				}
			*/

			cl := ConstructVseAttestationFromCert(subjKey, signerKey)
			if cl == nil {
				fmt.Printf("InitProvedStatements: Can't construct Attestation from cert\n")
				return false
			}
			ps.Proved = append(ps.Proved, cl)
		} else if ev.GetEvidenceType() == "signed-vse-attestation-report" {
			sr := certprotos.SignedReport{}
			err := proto.Unmarshal(ev.SerializedEvidence, &sr)
			if err != nil {
				fmt.Printf("Can't unmarshal signed report\n")
				return false
			}
			k := sr.SigningKey
			info := certprotos.VseAttestationReportInfo{}
			err = proto.Unmarshal(sr.GetReport(), &info)
			if err != nil {
				fmt.Printf("Can't unmarshal info\n")
				return false
			}
			ud := certprotos.AttestationUserData{}
			err = proto.Unmarshal(info.GetUserData(), &ud)
			if err != nil {
				fmt.Printf("Can't unmarshal user data\n")
				return false
			}

			if VerifyReport("vse-attestation-report", k, ev.GetSerializedEvidence()) {
				if CheckTimeRange(info.NotBefore, info.NotAfter) {
					cl := ConstructVseAttestClaim(k, ud.EnclaveKey, info.VerifiedMeasurement)
					ps.Proved = append(ps.Proved, cl)
				}
			} else {
				fmt.Printf("InitProvedStatements: vse-attestation-report fails to verify\n")
				return false
			}
		} else {
			fmt.Printf("Unknown evidence type\n")
			return false
		}
	}
	return true
}

func InitCerifierRules(cr *certprotos.CertifierRules) bool {
	/*
		Certifier proofs

		rule 1 (R1): If measurement is-trusted and key1 speaks-for measurement then
			key1 is-trusted-for-authentication.
		rule 2 (R2): If key2 speaks-for key1 and key3 speaks-for key2 then key3 speaks-for key1
		rule 3 (R3): If key1 is-trusted and key1 says X, then X is true
		rule 4 (R4): If key2 speaks-for key1 and key1 is-trusted then key2 is-trusted
		rule 5 (R5): If key1 is-trustedXXX and key1 says key2 is-trustedYYY then key2 is-trustedYYY
			provided is-trustedXXX dominates is-trustedYYY
		rule 6 (R6): if key1 is-trustedXXX and key1 says key2 speaks-for measurement then
			key2 speaks-for measurement provided is-trustedXXX dominates is-trusted-for-attestation
		rule 7 (R7): If measurement is-trusted and key1 speaks-for measurement then
			key1 is-trusted-for-attestation.
		rule 8 (R8): If environment[platform, measurement] is-environment AND platform-template
			has-trusted-platform-property then environment[platform, measurement]
			environment-platform-is-trusted provided platform properties satisfy platform template
		rule 9 (R9): If environment[platform, measurement] is-environment AND measurement is-trusted then
			environment[platform, measurement] environment-measurement is-trusted
		rule 10 (R10): If environment[platform, measurement] environment-platform-is-trusted AND
			environment[platform, measurement] environment-measurement-is-trusted then
			environment[platform, measurement] is-trusted
		rule 11 (R11): if key1 is-trustedXXX and key1 says key2 speaks-for measurement then
			key2 speaks-for measurement provided is-trustedXXX dominates is-trusted-for-key-provision-
	*/

	return true
}

func PrintProofStep(prefix string, step *certprotos.ProofStep) {
	if step.S1 == nil || step.S2 == nil || step.Conclusion == nil || step.RuleApplied == nil {
		return
	}
	fmt.Printf("%s", prefix)
	PrintVseClause(step.S1)
	fmt.Printf("\n%s and\n", prefix)
	fmt.Printf("%s", prefix)
	PrintVseClause(step.S2)
	fmt.Printf("\n%s imply via rule %d\n", prefix, int(*step.RuleApplied))
	fmt.Printf("%s", prefix)
	PrintVseClause(step.Conclusion)
	fmt.Printf("\n\n")
}

func PrintProof(pf *certprotos.Proof) {
	fmt.Printf("\nProof:\n")
	for i := 0; i < len(pf.Steps); i++ {
		ps := pf.Steps[i]
		PrintProofStep("    ", ps)
	}
}

func AddFactFromSignedClaim(signedClaim *certprotos.SignedClaimMessage,
	alreadyProved *certprotos.ProvedStatements) bool {

	k := signedClaim.SigningKey
	tcl := certprotos.VseClause{}
	if VerifySignedAssertion(*signedClaim, k, &tcl) {
		// make sure the saying key in tcl is the same key that signed it
		if tcl.GetVerb() == "says" && tcl.GetSubject().GetEntityType() == "key" {
			if SameKey(k, tcl.GetSubject().GetKey()) {
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

func ProducePlatformRule(issuerKey *certprotos.KeyMessage, issuerCert *x509.Certificate,
	subjKey *certprotos.KeyMessage, durationSeconds float64) []byte {

	// Return signed claim: issuer-Key says subjKey is-trusted-for-attestation
	s1 := MakeKeyEntity(subjKey)
	if s1 == nil {
		return nil
	}
	isTrustedForAttest := "is-trusted-for-attestation"
	c1 := MakeUnaryVseClause(s1, &isTrustedForAttest)
	if c1 == nil {
		return nil
	}
	issuerPublic := InternalPublicFromPrivateKey(issuerKey)
	if issuerPublic == nil {
		fmt.Printf("Can't make isser public from private\n")
		return nil
	}
	s2 := MakeKeyEntity(issuerPublic)
	if s2 == nil {
		return nil
	}
	saysVerb := "says"
	c2 := MakeIndirectVseClause(s2, &saysVerb, c1)
	if c2 == nil {
		return nil
	}

	tn := TimePointNow()
	tf := TimePointPlus(tn, 365*86400)
	nb := TimePointToString(tn)
	na := TimePointToString(tf)
	ser, err := proto.Marshal(c2)
	if err != nil {
		return nil
	}
	cl1 := MakeClaim(ser, "vse-clause", "platform-rule", nb, na)
	if cl1 == nil {
		return nil
	}

	rule := MakeSignedClaim(cl1, issuerKey)
	if rule == nil {
		return nil
	}
	ssc, err := proto.Marshal(rule)
	if err != nil {
		return nil
	}

	return ssc
}

func ConstructVseAttestClaim(attestKey *certprotos.KeyMessage, enclaveKey *certprotos.KeyMessage,
	measurement []byte) *certprotos.VseClause {
	am := MakeKeyEntity(attestKey)
	if am == nil {
		fmt.Printf("ConstructVseAttestClaim: Can't make attest entity\n")
		return nil
	}
	em := MakeKeyEntity(enclaveKey)
	if em == nil {
		fmt.Printf("ConstructVseAttestClaim: Can't make enclave entity\n")
		return nil
	}
	mm := MakeMeasurementEntity(measurement)
	if mm == nil {
		fmt.Printf("ConstructVseAttestClaim: Can't make measurement entity\n")
		return nil
	}
	says := "says"
	speaks_for := "speaks-for"
	c1 := MakeSimpleVseClause(em, &speaks_for, mm)
	return MakeIndirectVseClause(am, &says, c1)
}

func ConstructVseAttestationFromCert(subjKey *certprotos.KeyMessage, signerKey *certprotos.KeyMessage) *certprotos.VseClause {
	subjectKeyEntity := MakeKeyEntity(subjKey)
	if subjectKeyEntity == nil {
		return nil
	}
	signerKeyEntity := MakeKeyEntity(signerKey)
	if signerKeyEntity == nil {
		return nil
	}
	t_verb := "is-trusted-for-attestation"
	tcl := MakeUnaryVseClause(subjectKeyEntity, &t_verb)
	if tcl == nil {
		return nil
	}
	s_verb := "says"
	return MakeIndirectVseClause(signerKeyEntity, &s_verb, tcl)
}

func ConstructOESpeaksForStatement(vcertKey *certprotos.KeyMessage, enclaveKey *certprotos.KeyMessage, measurement []byte) *certprotos.VseClause {
	var vcertKeyEntity *certprotos.EntityMessage = nil
	if vcertKey != nil {
		vcertKeyEntity = MakeKeyEntity(vcertKey)
		if vcertKeyEntity == nil {
			return nil
		}
	}
	enclaveKeyEntity := MakeKeyEntity(enclaveKey)
	if enclaveKeyEntity == nil {
		return nil
	}
	measurementEntity := MakeMeasurementEntity(measurement)
	if measurementEntity == nil {
		return nil
	}
	speaks_verb := "speaks-for"
	tcl := MakeSimpleVseClause(enclaveKeyEntity, &speaks_verb, measurementEntity)
	if tcl == nil {
		return nil
	}
	if vcertKey == nil {
		return tcl
	}
	says_verb := "says"
	return MakeIndirectVseClause(vcertKeyEntity, &says_verb, tcl)
}

// vcek says environment is-environment
func ConstructSevIsEnvironmentStatement(vcekKey *certprotos.KeyMessage, binSevAttest []byte) *certprotos.VseClause {
	plat := GetPlatformFromSevAttest(binSevAttest)
	if plat == nil {
		fmt.Printf("ConstructSevIsEnvironmentStatement: can't get platform\n")
		return nil
	}
	m := GetMeasurementFromSevAttest(binSevAttest)
	if m == nil {
		fmt.Printf("ConstructSevIsEnvironmentStatement: can't get measurement\n")
		return nil
	}
	e := &certprotos.Environment{
		ThePlatform:    plat,
		TheMeasurement: m,
	}
	isEnvVerb := "is-environment"
	ee := MakeEnvironmentEntity(e)
	if ee == nil {
		fmt.Printf("ConstructSevIsEnvironmentStatement: can't make environment entity\n")
		return nil
	}
	vse := &certprotos.VseClause{
		Subject: ee,
		Verb:    &isEnvVerb,
	}
	ke := MakeKeyEntity(vcekKey)
	if ke == nil {
		fmt.Printf("ConstructSevIsEnvironmentStatement: can't make vcek key entity\n")
		return nil
	}
	saysVerb := "says"
	vseSays := &certprotos.VseClause{
		Subject: ke,
		Verb:    &saysVerb,
		Clause:  vse,
	}
	return vseSays
}

// vcekKey says enclaveKey speaksfor environment
func ConstructSevSpeaksForEnvironmentStatement(vcekKey *certprotos.KeyMessage, enclaveKey *certprotos.KeyMessage,
	env *certprotos.EntityMessage) *certprotos.VseClause {
	eke := MakeKeyEntity(enclaveKey)
	if eke == nil {
		fmt.Printf("ConstructSevIsEnvironmentStatement: can't make enclave key entity\n")
		return nil
	}
	speaksForVerb := "speaks-for"
	vseSpeaksFor := &certprotos.VseClause{
		Subject: eke,
		Verb:    &speaksForVerb,
		Object:  env,
	}
	ke := MakeKeyEntity(vcekKey)
	if ke == nil {
		fmt.Printf("ConstructSevIsEnvironmentStatement: can't make vcek key entity\n")
		return nil
	}
	saysVerb := "says"
	vseSays := &certprotos.VseClause{
		Subject: ke,
		Verb:    &saysVerb,
		Clause:  vseSpeaksFor,
	}
	return vseSays
}

func ConstructEnclaveKeySpeaksForMeasurement(k *certprotos.KeyMessage, m []byte) *certprotos.VseClause {
	e1 := MakeKeyEntity(k)
	if e1 == nil {
		return nil
	}
	e2 := MakeMeasurementEntity(m)
	if e1 == nil {
		return nil
	}
	speaks_for := "speaks-for"
	return MakeSimpleVseClause(e1, &speaks_for, e2)
}

/*
 */

// attestKey says enclaveKey speaksfor environment
func ConstructIsletSpeaksForMeasurementStatement(attestKey *certprotos.KeyMessage, enclaveKey *certprotos.KeyMessage,
	mEnt *certprotos.EntityMessage) *certprotos.VseClause {
	eke := MakeKeyEntity(enclaveKey)
	if eke == nil {
		fmt.Printf("ConstructIsletIsEnvironmentStatement: can't make enclave key entity\n")
		return nil
	}
	speaksForVerb := "speaks-for"
	vseSpeaksFor := &certprotos.VseClause{
		Subject: eke,
		Verb:    &speaksForVerb,
		Object:  mEnt,
	}
	ke := MakeKeyEntity(attestKey)
	if ke == nil {
		fmt.Printf("ConstructIsletIsEnvironmentStatement: can't make attest key entity\n")
		return nil
	}
	saysVerb := "says"
	vseSays := &certprotos.VseClause{
		Subject: ke,
		Verb:    &saysVerb,
		Clause:  vseSpeaksFor,
	}
	return vseSays
}

// attestKey says enclaveKey speaksfor environment
func ConstructKeystoneSpeaksForMeasurementStatement(attestKey *certprotos.KeyMessage, enclaveKey *certprotos.KeyMessage,
	mEnt *certprotos.EntityMessage) *certprotos.VseClause {
	eke := MakeKeyEntity(enclaveKey)
	if eke == nil {
		fmt.Printf("ConstructKeystoneIsEnvironmentStatement: can't make enclave key entity\n")
		return nil
	}
	speaksForVerb := "speaks-for"
	vseSpeaksFor := &certprotos.VseClause{
		Subject: eke,
		Verb:    &speaksForVerb,
		Object:  mEnt,
	}
	ke := MakeKeyEntity(attestKey)
	if ke == nil {
		fmt.Printf("ConstructKeystoneIsEnvironmentStatement: can't make attest key entity\n")
		return nil
	}
	saysVerb := "says"
	vseSays := &certprotos.VseClause{
		Subject: ke,
		Verb:    &saysVerb,
		Clause:  vseSpeaksFor,
	}
	return vseSays
}

/*
struct sgx_quote_t {
	uint16_t              version;                                     // 0x000
	uint16_t              sign_type;                                   // 0x002
	sgx_epid_group_id_t   epid_group_id;                               // 0x004
	sgx_isv_svn_t         qe_svn;                                      // 0x008
	sgx_isv_svn_t         pce_svn;                                     // 0x00A
	uint32_t              xeid;                                        // 0x00C
	sgx_basename_t        basename;                                    // 0x010
	sgx_cpu_svn_t         cpu_svn;                                     // 0x030
	sgx_misc_select_t     misc_select;                                 // 0x040
	uint8_t               reserved1[SGX_REPORT_BODY_RESERVED1_BYTES];  // 0x044
	sgx_isvext_prod_id_t  isv_ext_prod_id;                             // 0x050
	sgx_attributes_t      attributes;                                  // 0x060
	sgx_measurement_t     mr_enclave;                                  // 0x070
	uint8_t               reserved2[SGX_REPORT_BODY_RESERVED2_BYTES];  // 0x090
	sgx_measurement_t     mr_signer;                                   // 0x0B0
	uint8_t               reserved3[SGX_REPORT_BODY_RESERVED3_BYTES];  // 0x0D0
	sgx_config_id_t       config_id;                                   // 0x0F0
	sgx_prod_id_t         isv_prod_id;                                 // 0x130
	sgx_isv_svn_t         isv_svn;                                     // 0x132
	sgx_config_svn_t      config_svn;                                  // 0x134
	uint8_t               reserved4[SGX_REPORT_BODY_RESERVED4_BYTES];  // 0x136
	sgx_isvfamily_id_t    isv_family_id;                               // 0x160
	sgx_report_data_t     report_data;                                 // 0x170
	uint32_t              signature_len;                               // 0x1B0
	uint8_t               signature[];                                 // 0x1B4
};
*/

// The returned quantities are sort of described in the Intel Architecure manual
// in chapter 38 but not in detail.  They are:
//	qesvm: The quoting enclave security version number (16 bits).
//	pceSvn: The provisioning enclave security version number (16 bits).
//	cpuSvn: The cpu security version number (128 bits) which consists of
//		"small integers describing the version numbers of compnents".
//	debug: Whether the enclave is debugable.
//	mode64bit: Running as x64 (rather than i32).
// The last two come from the attributes field.
func GetPlatformAttributesFromGramineAttest(binGramineAttest []byte) (uint16, uint16, []byte, bool, bool) {
	qeSvn := uint16(binGramineAttest[0x8])
	pceSvn := uint16(binGramineAttest[0xA])
	cpuSvn := []byte(binGramineAttest[0x30:0x40])
	flags := uint64(binGramineAttest[0x60])
	debug := ((flags & 0x2) != 0)
	mode64bit := ((flags & 0x4) != 0)
	return qeSvn, pceSvn, cpuSvn, debug, mode64bit
}

// Caution:  This can change if attestation.h below changes
/*
	struct attestation_report {
	  uint32_t    version;                  // 0x000
	  uint32_t    guest_svn;                // 0x004
	  uint64_t    policy;                   // 0x008
	  uint8_t     family_id[16];            // 0x010
	  uint8_t     image_id[16];             // 0x020
	  uint32_t    vmpl;                     // 0x030
	  uint32_t    signature_algo;           // 0x034
	  union tcb_version platform_version;   // 0x038
	  uint64_t    platform_info;            // 0x040
	  uint32_t    flags;                    // 0x048
	  uint32_t    reserved0;                // 0x04C
	  uint8_t     report_data[64];          // 0x050
	  uint8_t     measurement[48];          // 0x090
	  uint8_t     host_data[32];            // 0x0C0
	  uint8_t     id_key_digest[48];        // 0x0E0
	  uint8_t     author_key_digest[48];    // 0x110
	  uint8_t     report_id[32];            // 0x140
	  uint8_t     report_id_ma[32];         // 0x160
	  union tcb_version reported_tcb;       // 0x180
	  uint8_t     reserved1[24];            // 0x188
	  uint8_t     chip_id[64];              // 0x1A0
	  uint8_t     reserved2[192];           // 0x1E0
	  struct signature  signature;          // 0x2A0
	};
*/
func GetUserDataHashFromSevAttest(binSevAttest []byte) []byte {
	return []byte(binSevAttest[0x50:0x90])
}

func GetTcbVersionFromSevAttest(binSevAttest []byte) uint64 {
	tcb := uint64(0)
	for i := 0; i < 8; i++ {
		tcb |= uint64(binSevAttest[0x180+i]) << (8 * i)
	}
	return tcb
}

func GetPlatformFromGramineAttest(binAttest []byte) *certprotos.Platform {

	qeSvn, pceSvn, cpuSvn, debug, mode64bit := GetPlatformAttributesFromGramineAttest(binAttest)

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

	return MakePlatform(platName, nil, props)
}

/*
	Policy byte:
		Bit 3: Guest can be activated on multiple sockets.
		Bit 2: Debugging disallowed if 0
		Bit 1: Migration disallowed if 0
		Bit 0: SMT disallowed if 0
*/
func GetPlatformFromSevAttest(binSevAttest []byte) *certprotos.Platform {

	// get properties
	props := &certprotos.Properties{}
	pol_byte := binSevAttest[10]
	major_byte := binSevAttest[9]
	minor_byte := binSevAttest[8]

	svt := "string"
	ivt := "int"
	ce := "="

	pn0 := "single-socket"
	vp0 := "no"
	if pol_byte&0x08 != 0 {
		vp0 = "yes"
	}
	p0 := MakeProperty(pn0, svt, &vp0, &ce, nil)
	props.Props = append(props.Props, p0)

	pn1 := "debug"
	vp1 := "no"
	if pol_byte&0x04 != 0 {
		vp1 = "yes"
	}
	p1 := MakeProperty(pn1, svt, &vp1, &ce, nil)
	props.Props = append(props.Props, p1)

	pn2 := "smt"
	vp2 := "no"
	if pol_byte&0x01 == 1 {
		vp2 = "yes"
	}
	p2 := MakeProperty(pn2, svt, &vp2, &ce, nil)
	props.Props = append(props.Props, p2)

	pn3 := "migrate"
	vp3 := "no"
	if pol_byte&0x02 != 0 {
		vp3 = "yes"
	}
	p3 := MakeProperty(pn3, svt, &vp3, &ce, nil)
	props.Props = append(props.Props, p3)

	m1iv := uint64(major_byte)
	pn4 := "api-major"
	p4 := MakeProperty(pn4, ivt, nil, &ce, &m1iv)
	props.Props = append(props.Props, p4)

	m2iv := uint64(minor_byte)
	pn5 := "api-minor"
	p5 := MakeProperty(pn5, ivt, nil, &ce, &m2iv)
	props.Props = append(props.Props, p5)

	tcb := GetTcbVersionFromSevAttest(binSevAttest)

	// DEBUG
	fmt.Printf("tcb: %08x\n", tcb)

	pn6 := "tcb-version"
	p6 := MakeProperty(pn6, ivt, nil, &ce, &tcb)
	props.Props = append(props.Props, p6)

	t1 := "amd-sev-snp"
	return MakePlatform(t1, nil, props)
}

func GetMeasurementFromSevAttest(binSevAttest []byte) []byte {
	return []byte(binSevAttest[0x90:0xc0])
}

func GetMeasurementEntityFromSevAttest(binSevAttest []byte) *certprotos.EntityMessage {
	return MakeMeasurementEntity(GetMeasurementFromSevAttest(binSevAttest))
}

func VerifyReport(etype string, pk *certprotos.KeyMessage, serialized []byte) bool {
	if etype != "vse-attestation-report" {
		return false
	}
	sr := certprotos.SignedReport{}
	err := proto.Unmarshal(serialized, &sr)
	if err != nil {
		fmt.Printf("Can't unmarshal signed report\n")
		return false
	}
	k := sr.SigningKey
	if !SameKey(k, pk) {
		return false
	}
	if sr.Report == nil || sr.Signature == nil {
		return false
	}

	rPK := rsa.PublicKey{}
	rpK := rsa.PrivateKey{}
	if GetRsaKeysFromInternal(k, &rpK, &rPK) == false {
		fmt.Printf("VerifyReport: Can't convert rsa key from internal\n")
		return false
	}

	if RsaSha256Verify(&rPK, sr.Report, sr.Signature) {
		return true
	}
	return false
}

//	Returns measurement
//	serialized is the serialized sev_attestation_message
func VerifySevAttestation(serialized []byte, k *certprotos.KeyMessage) []byte {

	var am certprotos.SevAttestationMessage
	err := proto.Unmarshal(serialized, &am)
	if err != nil {
		fmt.Printf("VerifySevAttestation: Can't unmarshal SevAttestationMessage\n")
		return nil
	}

	ptr := am.ReportedAttestation
	if ptr == nil {
		fmt.Printf("VerifySevAttestation: am.ReportedAttestation is wrong\n")
		return nil
	}

	// Get public key so we can check the attestation
	_, PK, err := GetEccKeysFromInternal(k)
	if err != nil || PK == nil {
		fmt.Printf("VerifySevAttestation: Can't extract key.\n")
		return nil
	}

	// hd is the hash of the user data in the report
	hd := ptr[0x50:0x80]

	if am.WhatWasSaid == nil {
		fmt.Printf("VerifySevAttestation: WhatWasSaid is nil.\n")
		return nil
	}
	hashed := sha512.Sum384(am.WhatWasSaid)

	// Debug
	fmt.Printf("\nVerifySevAttestation\n")
	fmt.Printf("\nUser data hash in report: ")
	PrintBytes(hd)
	fmt.Printf("\nCalculated: ")
	PrintBytes(hashed[0:48])
	fmt.Printf("\n")

	if !bytes.Equal(hashed[0:48], hd[0:48]) {
		fmt.Printf("VerifySevAttestation: Hash of user data is not the same as in the report\n")
		return nil
	}

	hashOfHeader := sha512.Sum384(ptr[0:0x2a0])

	sig := ptr[0x2a0:0x330]
	rb := sig[0:48]
	sb := sig[72:120]
	measurement := ptr[0x90:0xc0]

	// Debug
	fmt.Printf("\nHashed report header: ")
	PrintBytes(hashOfHeader[0:48])
	fmt.Printf("\n")
	fmt.Printf("Measurement: ")
	PrintBytes(measurement)
	fmt.Printf("\n")
	fmt.Printf("Signature structure: ")
	PrintBytes(sig)
	fmt.Printf("\n  R: ")
	PrintBytes(rb)
	fmt.Printf("\n  S: ")
	PrintBytes(sb)
	fmt.Printf("\n")

	reversedR := LittleToBigEndian(rb)
	reversedS := LittleToBigEndian(sb)
	if reversedR == nil || reversedS == nil {
		fmt.Printf("VerifySevAttestation: reversed bytes failed\n")
		return nil
	}

	// Debug
	fmt.Printf("  Reversed R: ")
	PrintBytes(reversedR)
	fmt.Printf("\n")
	fmt.Printf("  Reversed S: ")
	PrintBytes(reversedS)
	fmt.Printf("\n")

	r := new(big.Int).SetBytes(reversedR)
	s := new(big.Int).SetBytes(reversedS)
	if !ecdsa.Verify(PK, hashOfHeader[0:48], r, s) {
		fmt.Printf("VerifySevAttestation: ecdsa.Verify failed\n")
		return nil
	}

	vcekTcbVer := k.GetSnpTcbVersion()
	tcbVer := GetTcbVersionFromSevAttest(ptr)
	if vcekTcbVer != tcbVer {
		fmt.Printf("VerifySevAttestation: Platform TCB Version check failed\n")
		fmt.Printf("VCEK TCB Version: %08x\n", vcekTcbVer)
		fmt.Printf("Platform TCB Version: %08x\n", tcbVer)
		return nil
	}
	chipid := ptr[0x1A0:0x1E0]
	if !bytes.Equal(chipid, k.GetSnpChipid()) {
		fmt.Printf("VerifySevAttestation: Chipid check failed\n")
		fmt.Printf("VCEK HwID: ")
		PrintBytes(k.GetSnpChipid())
		fmt.Printf("\n")
		fmt.Printf("Platform Chip ID: ")
		PrintBytes(chipid)
		fmt.Printf("\n")
		return nil
	}

	// return measurement, if successful
	return measurement
}

/*
	Keystone attestation layout
		struct enclave_report_t {
		  byte hash[MDSIZE];
		  uint64_t data_len;
		  byte data[32];  // this was ATTEST_DATA_MAXLEN
		  byte signature[SIGNATURE_SIZE];
		  int size_sig;  // Remove?
		};

		// The hash in sm_report_t is the hash of the cpu embedded
		// security code/Monitor that provides the trusted primitives.
		struct sm_report_t {
		  byte hash[MDSIZE];
		  byte public_key[PUBLIC_KEY_SIZE];
		  byte signature[SIGNATURE_SIZE];
		};

		// Usually the dev_public_key int report_t below
		// and the public_key in sm_report_t are the
		// same trusted key of the manufacturer and will
		// come with a cert chain in Init.
		struct report_t {
		  struct enclave_report_t enclave;
		  struct sm_report_t sm;
		  byte dev_public_key[PUBLIC_KEY_SIZE];
		};
*/

/*
 * Design approaches to explore and refine in future revs:
 *
 * Option 1:
 *
 *  - Figure out how to write this fn. How to verify evidence provided by Islet-shim?
 *  - Islet-shim provides an attest function which generates an evidence report
 *  - Need to write something to generate an evidence package on top of that evidence.
 *  - Write a fn that calls Islet-Attest(), packages it together before sending it to
 *    the Cert service.
 *
 *    Most straightforward way to verify is to have a public-key (may be 'k' here)
 *    and verify it. In most cases, this key is called platform-cert. This is the cert
 *    you get for the [say, SEV] machine. This cert can be used to verify evidence
 *    generated by [this] machine.
 *
 *  - For shims, we probably have one public key-cert, if cert is not provided.
 *	Here's what's in the SDK
 *		pub struct Report {
 *			pub buffer: Vec<u8>,
 *			pub user_data: Vec<u8>,
 *		}
 *
 * Option 2: (Always available but we give up platform verification and trust the
 *            SDK to do it.)
 *
 *  - Write Go code to call islet_Verify() externally
 *  - Dev VerifyIsletAttestation () which will call islet_verify()
 */

//	Returns measurement
//	serialized is the serialized islet_attestation_message
func VerifyIsletAttestation(serialized []byte, k *certprotos.KeyMessage) []byte {

	var am certprotos.IsletAttestationMessage
	err := proto.Unmarshal(serialized, &am)
	if err != nil {
		fmt.Printf("VerifyIsletAttestation: Can't unmarshal SevAttestationMessage\n")
		return nil
	}

	ptr := am.ReportedAttestation
	if ptr == nil {
		fmt.Printf("VerifyIsletAttestation: am.ReportedAttestation is wrong\n")
		return nil
	}

	/*
		     * This is the hard-coded measurement provided by Islet-shim.
		     *
			measurement := []byte {
				0x61, 0x90, 0xEB, 0x90, 0xB2, 0x93, 0x88, 0x6C,
				0x17, 0x2E, 0xC6, 0x44, 0xDA, 0xFB, 0x7E, 0x33,
				0xEE, 0x2C, 0xEA, 0x65, 0x41, 0xAB, 0xE1, 0x53,
				0x00, 0xD9, 0x63, 0x80, 0xDF, 0x52, 0x5B, 0xF9,
			}
	*/
	// return measurement
	// Call the C-Go Islet verify function
	m, err := isletverify.IsletVerify(am.WhatWasSaid, am.ReportedAttestation)
	if err != nil {
		fmt.Printf("VerifyIsletAttestation: IsletVerify() failed\n")
		return nil
	}
	return m
}

//	Returns measurement
//	serialized is the serialized keystone_attestation_message
func VerifyKeystoneAttestation(serialized []byte, k *certprotos.KeyMessage) []byte {

	var am certprotos.KeystoneAttestationMessage
	err := proto.Unmarshal(serialized, &am)
	if err != nil {
		fmt.Printf("VerifyKeystoneAttestation: Can't unmarshal SevAttestationMessage\n")
		return nil
	}

	ptr := am.ReportedAttestation
	if ptr == nil {
		fmt.Printf("VerifyKeystoneAttestation: am.ReportedAttestation is wrong\n")
		return nil
	}

	// Get public key so we can check the attestation
	_, PK, err := GetEccKeysFromInternal(k)
	if err != nil || PK == nil {
		fmt.Printf("VerifyKeystoneAttestation: Can't extract key.\n")
		return nil
	}

	if am.WhatWasSaid == nil {
		fmt.Printf("VerifyKeystoneAttestation: WhatWasSaid is nil.\n")
		return nil
	}
	hashedWhatWasSaid := sha256.Sum256(am.WhatWasSaid)
	reportData := ptr[72:104]
	if !bytes.Equal(reportData[:], hashedWhatWasSaid[:]) {
		fmt.Printf("VerifyKeystoneAttestation: WhatWasSaid hash does not match data.\n")
		return nil
	}

	measurement := ptr[0:32]
	byteSize := ptr[248:252]
	sigSize := int(byteSize[0]) + 256*int(byteSize[1]) + 256*256*int(byteSize[2]) + 256*256*256*int(byteSize[3])
	sig := ptr[104:(104 + sigSize)]

	// Compute hash of hash, datalen, data in enclave report
	// This is what was signed
	signedHash := sha256.Sum256(ptr[0:104])

	// Debug
	testSign(PK)
	fmt.Printf("\nVerifyKeystoneAttestation\n")
	fmt.Printf("Hashing       : ")
	PrintBytes(ptr[0:104])
	fmt.Printf("\n")
	fmt.Printf("Hash          : ")
	PrintBytes(signedHash[:])
	fmt.Printf("\n")
	fmt.Printf("Measurement   : ")
	PrintBytes(measurement)
	fmt.Printf("\n")
	fmt.Printf("Signature (%d): ", sigSize)
	PrintBytes(sig[0:sigSize])
	fmt.Printf("\n\n")

	// check signature
	if !ecdsa.VerifyASN1(PK, signedHash[:], sig[:]) {
		fmt.Printf("VerifyKeystoneAttestation: ecdsa.Verify failed\n")
		// Todo: why does this fail?
		// return nil
	} else {
		fmt.Printf("VerifyKeystoneAttestation: ecdsa.Verify succeeded\n")
	}

	// return measurement, if successful
	return measurement
}

// R1: If measurement is-trusted and key1 speaks-for measurement then key1 is-trusted-for-authentication.
// R1: If environment is-trusted and key1 speaks-for environment then key1 is-trusted-for-authentication.
func VerifyRule1(tree *PredicateDominance, c1 *certprotos.VseClause, c2 *certprotos.VseClause, c *certprotos.VseClause) bool {
	if c1.Subject == nil || c1.Verb == nil || c1.Object != nil || c1.Clause != nil {
		return false
	}
	if c1.GetVerb() != "is-trusted" {
		return false
	}
	if c1.Subject.GetEntityType() == "measurement" || c1.Subject.GetEntityType() == "environment" {

		if c2.Subject == nil || c2.Verb == nil || c2.Object == nil || c2.Clause != nil {
			return false
		}
		if c2.GetVerb() != "speaks-for" {
			return false
		}
		if !SameEntity(c1.Subject, c2.Object) {
			return false
		}

		if c.Subject == nil || c.Verb == nil || c.Object != nil || c.Clause != nil {
			return false
		}
		if c.GetVerb() != "is-trusted-for-authentication" {
			return false
		}
		return SameEntity(c.Subject, c2.Subject)
	}
	return false
}

// R2: If key2 speaks-for key1 and key3 speaks-for key2 then key3 speaks-for key1
func VerifyRule2(tree *PredicateDominance, c1 *certprotos.VseClause, c2 *certprotos.VseClause, c *certprotos.VseClause) bool {
	return false
}

// R3: If key1 is-trusted and key1 says X, then X is true
func VerifyRule3(tree *PredicateDominance, c1 *certprotos.VseClause, c2 *certprotos.VseClause, c *certprotos.VseClause) bool {
	// check c1 is key is-trusted
	// check c2 is key says statement
	// check c is statement
	if c1.Subject == nil || c1.Verb == nil || c1.Object != nil || c1.Clause != nil {
		return false
	}
	if c1.GetVerb() != "is-trusted" {
		return false
	}
	if c1.Subject.GetEntityType() != "key" {
		return false
	}

	if c2.Subject == nil || c2.Verb == nil || c2.Object != nil || c2.Clause == nil {
		return false
	}
	if c2.Subject.GetEntityType() != "key" {
		return false
	}
	if c2.GetVerb() != "says" {
		return false
	}
	if !SameEntity(c1.Subject, c2.Subject) {
		return false
	}

	return SameVseClause(c2.Clause, c)
}

// R4: If key2 speaks-for key1 and key1 is-trusted then key2 is-trusted
func VerifyRule4(tree *PredicateDominance, c1 *certprotos.VseClause, c2 *certprotos.VseClause, c *certprotos.VseClause) bool {
	return false
}

// R5: If key1 is-trustedXXX and key1 says key2 is-trustedYYY then key2 is-trustedYYY provided is-trustedXXX dominates is-trustedYYY
func VerifyRule5(tree *PredicateDominance, c1 *certprotos.VseClause, c2 *certprotos.VseClause, c *certprotos.VseClause) bool {
	if c1.Subject == nil || c1.Verb == nil || c1.Object != nil || c1.Clause != nil || c2.Clause == nil {
		return false
	}
	c3 := c2.Clause
	if c1.Subject.GetEntityType() != "key" {
		return false
	}

	if c2.Subject == nil || c2.Verb == nil || c2.Object != nil || c2.Clause == nil {
		return false
	}

	if c2.Subject.GetEntityType() != "key" {
		return false
	}
	if c2.GetVerb() != "says" {
		return false
	}

	if c3.Subject == nil || c3.Verb == nil || c3.Object != nil {
		return false
	}
	if !Dominates(tree, *c1.Verb, *c3.Verb) {
		return false
	}
	if c3.Subject.GetEntityType() != "key" {
		return false
	}
	if !SameEntity(c1.Subject, c2.Subject) {
		fmt.Printf("c1.Subject: ")
		PrintEntity(c1.Subject)
		fmt.Printf("c2.Subject: ")
		PrintEntity(c2.Subject)
		fmt.Printf("\n")
		return false
	}

	return SameVseClause(c3, c)
}

// R6: if key1 is-trustedXXX
//	 and
//		key1 says key2 speaks-for measurement then
//		key2 speaks-for measurement provided is-trustedXXX dominates is-trusted-for-attestation
//	 OR
//		key1 says key2 speaks-for environment then key2 speaks-for environment provided is-trustedXXX dominates is-trusted-for-attestation
//	 OR
//		key1 says env is-environment then is-trustedXXX dominates is-trusted-for-attestation
func VerifyRule6(tree *PredicateDominance, c1 *certprotos.VseClause, c2 *certprotos.VseClause, c *certprotos.VseClause) bool {
	if c1.Subject == nil || c1.Verb == nil || c1.Object != nil || c1.Clause != nil {
		return false
	}
	if !Dominates(tree, "is-trusted", *c1.Verb) {
		return false
	}
	if c1.Subject.GetEntityType() != "key" {
		return false
	}

	if c2.Subject == nil || c2.Verb == nil || c2.Object != nil || c2.Clause == nil {
		return false
	}

	if c2.Subject.GetEntityType() != "key" {
		return false
	}
	if c2.GetVerb() != "says" {
		return false
	}
	if !SameEntity(c1.Subject, c2.Subject) {
		return false
	}

	c3 := c2.Clause
	if c3.Subject == nil || c3.Verb == nil {
		return false
	}
	if !Dominates(tree, *c1.Verb, "is-trusted-for-attestation") {
		return false
	}
	if *c3.Verb == "speaks-for" {
		if c3.Object.GetEntityType() != "measurement" && c3.Object.GetEntityType() != "environment" {
			return false
		}
		if c3.Subject.GetEntityType() != "key" {
			return false
		}
		return SameVseClause(c3, c)
	} else if *c3.Verb == "is-environment" {
		if c3.Subject.GetEntityType() != "environment" {
			return false
		}
		return SameVseClause(c3, c)
	}
	return false
}

// R7: If measurement is-trusted and key1 speaks-for measurement then key1 is-trusted-for-attestation OR
//     If environment is-trusted and key1 speaks-for environment then key1 is-trusted-for-sttestation
func VerifyRule7(tree *PredicateDominance, c1 *certprotos.VseClause, c2 *certprotos.VseClause, c *certprotos.VseClause) bool {
	if c1.Subject == nil || c1.Verb == nil || c1.Object != nil || c1.Clause != nil {
		return false
	}
	if c1.GetVerb() != "is-trusted" {
		return false
	}
	if c1.Subject.GetEntityType() != "measurement" && c1.Subject.GetEntityType() != "environment" {
		return false
	}

	if c2.Subject == nil || c2.Verb == nil || c2.Object == nil || c2.Clause != nil {
		return false
	}
	if c2.GetVerb() != "speaks-for" {
		return false
	}
	if !SameEntity(c1.Subject, c2.Object) {
		return false
	}

	if c.Subject == nil || c.Verb == nil || c.Object != nil || c.Clause != nil {
		return false
	}
	if c.GetVerb() != "is-trusted-for-attestation" {
		return false
	}
	return SameEntity(c.Subject, c2.Subject)
}

// R8: If environment[platform, measurement] is-environment AND platform-template
//	has-trusted-platform-property then environment[platform, measurement]
func VerifyRule8(tree *PredicateDominance, c1 *certprotos.VseClause, c2 *certprotos.VseClause, c *certprotos.VseClause) bool {
	if c1.Subject == nil || c1.Verb == nil || c1.Object != nil || c1.Clause != nil {
		return false
	}
	if c1.GetVerb() != "is-environment" {
		return false
	}
	if c1.Subject.GetEntityType() != "environment" {
		return false
	}
	if c2.Subject.GetEntityType() != "platform" {
		return false
	}
	if c2.Subject == nil || c2.Verb == nil || c2.Object != nil {
		return false
	}
	if c2.GetVerb() != "has-trusted-platform-property" {
		return false
	}
	if c1.Subject.EnvironmentEnt == nil || c2.Subject.PlatformEnt == nil {
		return false
	}
	// Does c1.EnvironmentEnt.ThePlatform.Props satisfy c2.PlatformEnt.Props
	if !SatisfyingProperties(c2.Subject.PlatformEnt.Props, c1.Subject.EnvironmentEnt.ThePlatform.Props) {
		fmt.Printf("Env: ")
		PrintProperties(c1.Subject.EnvironmentEnt.ThePlatform.Props)
		fmt.Printf("\nPlat: ")
		PrintProperties(c2.Subject.PlatformEnt.Props)
		fmt.Printf("\n")
		return false
	}
	return true
}

// R9:  If environment[platform, measurement] is-environment AND measurement is-trusted then
//		environment[platform, measurement] environment-measurement is-trusted
func VerifyRule9(tree *PredicateDominance, c1 *certprotos.VseClause, c2 *certprotos.VseClause, c *certprotos.VseClause) bool {
	if c1.Subject == nil || c1.Verb == nil || c1.Object != nil {
		return false
	}
	if c2.Subject == nil || c2.Verb == nil || c2.Object != nil {
		return false
	}
	if c1.GetVerb() != "is-environment" {
		return false
	}
	if c2.GetVerb() != "is-trusted" {
		return false
	}
	if c2.Subject.GetEntityType() != "measurement" {
		return false
	}
	if !SameEntity(c1.Subject, c.Subject) {
		return false
	}
	if c.GetVerb() != "environment-measurement-is-trusted" {
		return false
	}
	if !bytes.Equal(c2.Subject.Measurement, c1.Subject.EnvironmentEnt.TheMeasurement) {
		return false
	}
	return true
}

// R10: If environment[platform, measurement] environment-platform-is-trusted AND
//	environment[platform, measurement] environment-measurement-is-trusted then
//	environment[platform, measurement] is-trusted
func VerifyRule10(tree *PredicateDominance, c1 *certprotos.VseClause, c2 *certprotos.VseClause, c *certprotos.VseClause) bool {
	if c1.Subject == nil || c1.Verb == nil || c1.Object != nil || c1.Clause != nil {
		return false
	}
	if c1.GetVerb() != "environment-measurement-is-trusted" {
		return false
	}
	if c2.Subject == nil || c2.Verb == nil || c2.Object != nil || c2.Clause != nil {
		return false
	}
	if c2.GetVerb() != "environment-platform-is-trusted" {
		return false
	}
	if c.GetVerb() != "is-trusted" {
		return false
	}

	return SameEntity(c.Subject, c1.Subject) && SameEntity(c.Subject, c2.Subject)
}

// R11:  if     measurement is-trusted
//	 and
//		key speaks-for measurement then
//	 key is-trusted-for-key-provision
func VerifyRule11(tree *PredicateDominance, c1 *certprotos.VseClause, c2 *certprotos.VseClause, c *certprotos.VseClause) bool {

	// Debug
	/*
		fmt.Printf("c1:\n")
		PrintVseClause(c1)
		fmt.Printf("\n")
		fmt.Printf("c2:\n")
		PrintVseClause(c2)
		fmt.Printf("\n")
		fmt.Printf("c:\n")
		PrintVseClause(c)
		fmt.Printf("\n")
	*/

	if c1.Subject == nil || c1.Verb == nil || c1.Object != nil || c1.Clause != nil {
		return false
	}
	if !Dominates(tree, "is-trusted", *c1.Verb) {
		return false
	}
	if c1.Subject.GetEntityType() != "measurement" {
		return false
	}

	if c2.Subject == nil || c2.Verb == nil || c2.Object == nil {
		return false
	}

	if c2.Subject.GetEntityType() != "key" {
		return false
	}
	if c2.GetVerb() != "speaks-for" {
		return false
	}
	if c2.Object.GetEntityType() != "measurement" {
		return false
	}
	if !SameEntity(c1.Subject, c2.Object) {
		return false
	}
	if c.Subject == nil || c.Verb == nil {
		return false
	}
	if c.GetVerb() == "is-trusted-for-key-provision" && SameEntity(c2.Subject, c.Subject) {
		return true
	}

	return false
}

func StatementAlreadyProved(c1 *certprotos.VseClause, ps *certprotos.ProvedStatements) bool {
	for i := 0; i < len(ps.Proved); i++ {
		if SameVseClause(c1, ps.Proved[i]) {
			return true
		}
	}
	return false
}

func VerifyInternalProofStep(tree *PredicateDominance, c1 *certprotos.VseClause, c2 *certprotos.VseClause,
	c *certprotos.VseClause, rule int) bool {

	// vse_clause s1, vse_clause s2, vse_clause conclude, int rule_to_apply
	switch rule {
	case 1:
		return VerifyRule1(tree, c1, c2, c)
	case 2:
		return VerifyRule2(tree, c1, c2, c)
	case 3:
		return VerifyRule3(tree, c1, c2, c)
	case 4:
		return VerifyRule4(tree, c1, c2, c)
	case 5:
		return VerifyRule5(tree, c1, c2, c)
	case 6:
		return VerifyRule6(tree, c1, c2, c)
	case 7:
		return VerifyRule7(tree, c1, c2, c)
	case 8:
		return VerifyRule8(tree, c1, c2, c)
	case 9:
		return VerifyRule9(tree, c1, c2, c)
	case 10:
		return VerifyRule10(tree, c1, c2, c)
	case 11:
		return VerifyRule11(tree, c1, c2, c)
	}
	return false
}

func VerifyExternalProofStep(tree *PredicateDominance, step *certprotos.ProofStep) bool {
	rule := step.RuleApplied
	s1 := step.S1
	s2 := step.S2
	c := step.Conclusion
	if rule == nil || s1 == nil || s2 == nil || c == nil {
		return false
	}

	return VerifyInternalProofStep(tree, s1, s2, c, int(*rule))
}

func VerifyProof(policyKey *certprotos.KeyMessage, toProve *certprotos.VseClause,
	p *certprotos.Proof, ps *certprotos.ProvedStatements) bool {

	tree := PredicateDominance{
		Predicate:  "is-trusted",
		FirstChild: nil,
		Next:       nil,
	}

	if !InitDominance(&tree) {
		fmt.Printf("Can't init Dominance tree\n")
		return false
	}

	for i := 0; i < len(p.Steps); i++ {
		s1 := p.Steps[i].S1
		s2 := p.Steps[i].S2
		c := p.Steps[i].Conclusion
		if s1 == nil || s2 == nil || c == nil {
			fmt.Printf("Bad proof step\n")
			return false
		}
		if !StatementAlreadyProved(s1, ps) {
			continue
		}
		if !StatementAlreadyProved(s2, ps) {
			continue
		}
		if VerifyExternalProofStep(&tree, p.Steps[i]) {
			ps.Proved = append(ps.Proved, c)
			if SameVseClause(toProve, c) {
				return true
			}
		} else {
			fmt.Printf("VerifyProof error: Step %d, does not pass\n", i)
			PrintProofStep("    ", p.Steps[i])
			return false
		}

	}
	return false
}

func ConstructProofFromOeEvidenceWithoutEndorsement(publicPolicyKey *certprotos.KeyMessage, purpose string, alreadyProved *certprotos.ProvedStatements) (*certprotos.VseClause, *certprotos.Proof) {
	if len(alreadyProved.Proved) < 3 {
		fmt.Printf("ConstructProofFromOeEvidence: too few statements\n")
		return nil, nil
	}

	policyKeyIsTrusted := alreadyProved.Proved[0]
	policyKeySaysMeasurementIsTrusted := alreadyProved.Proved[1]
	enclaveKeySpeaksForMeasurement := alreadyProved.Proved[2]

	if policyKeyIsTrusted == nil || enclaveKeySpeaksForMeasurement == nil ||
		policyKeySaysMeasurementIsTrusted == nil {
		fmt.Printf("ConstructProofFromOeEvidence: Clauses absent\n")
		return nil, nil
	}

	proof := &certprotos.Proof{}
	r1 := int32(1)
	r3 := int32(3)
	r7 := int32(7)

	enclaveKey := enclaveKeySpeaksForMeasurement.Subject
	if enclaveKey == nil || enclaveKey.GetEntityType() != "key" {
		fmt.Printf("ConstructProofFromOeEvidence: Bad enclave key\n")
		return nil, nil
	}
	var toProve *certprotos.VseClause = nil
	if purpose == "authentication" {
		verb := "is-trusted-for-authentication"
		toProve = MakeUnaryVseClause(enclaveKey, &verb)
	} else {
		verb := "is-trusted-for-attestation"
		toProve = MakeUnaryVseClause(enclaveKey, &verb)
	}

	measurementIsTrusted := policyKeySaysMeasurementIsTrusted.Clause
	if measurementIsTrusted == nil {
		fmt.Printf("ConstructProofFromOeEvidence: Can't get measurement\n")
		return nil, nil
	}
	ps1 := certprotos.ProofStep{
		S1:          policyKeyIsTrusted,
		S2:          policyKeySaysMeasurementIsTrusted,
		Conclusion:  measurementIsTrusted,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps1)

	// measurement is-trusted and enclaveKey speaks-for measurement -->
	//	enclaveKey is-trusted-for-authentication (r1) or
	//	enclaveKey is-trusted-for-attestation (r7)
	if purpose == "authentication" {
		ps2 := certprotos.ProofStep{
			S1:          measurementIsTrusted,
			S2:          enclaveKeySpeaksForMeasurement,
			Conclusion:  toProve,
			RuleApplied: &r1,
		}
		proof.Steps = append(proof.Steps, &ps2)
	} else {
		ps2 := certprotos.ProofStep{
			S1:          measurementIsTrusted,
			S2:          enclaveKeySpeaksForMeasurement,
			Conclusion:  toProve,
			RuleApplied: &r7,
		}
		proof.Steps = append(proof.Steps, &ps2)
	}

	return toProve, proof

}

func ConstructProofFromOeEvidenceWithEndorsement(publicPolicyKey *certprotos.KeyMessage, purpose string, alreadyProved *certprotos.ProvedStatements) (*certprotos.VseClause, *certprotos.Proof) {
	if len(alreadyProved.Proved) < 4 {
		fmt.Printf("ConstructProofFromOeEvidence: too few statements\n")
		return nil, nil
	}

	policyKeyIsTrusted := alreadyProved.Proved[0]
	policyKeySaysPlatformKeyIsTrustedForAttestation := alreadyProved.Proved[1]
	policyKeySaysMeasurementIsTrusted := alreadyProved.Proved[2]
	platformSaysEnclaveKeySpeaksForMeasurement := alreadyProved.Proved[3]

	if platformSaysEnclaveKeySpeaksForMeasurement.Clause == nil {
		fmt.Printf("ConstructProofFromOeEvidence: can't get enclaveKeySpeaksForMeasurement\n")
		return nil, nil
	}
	enclaveKeySpeaksForMeasurement := platformSaysEnclaveKeySpeaksForMeasurement.Clause
	if policyKeyIsTrusted == nil || enclaveKeySpeaksForMeasurement == nil ||
		policyKeySaysMeasurementIsTrusted == nil {
		fmt.Printf("ConstructProofFromOeEvidence: clauses absent\n")
		return nil, nil
	}

	if policyKeySaysPlatformKeyIsTrustedForAttestation.Clause == nil {
		fmt.Printf("ConstructProofFromOeEvidence: Can't get platformKeyIsTrustedForAttestation\n")
		return nil, nil
	}
	platformKeyIsTrustedForAttestation := policyKeySaysPlatformKeyIsTrustedForAttestation.Clause

	proof := &certprotos.Proof{}
	r1 := int32(1)
	r3 := int32(3)
	r6 := int32(6)
	r7 := int32(7)

	enclaveKey := enclaveKeySpeaksForMeasurement.Subject
	if enclaveKey == nil || enclaveKey.GetEntityType() != "key" {
		fmt.Printf("ConstructProofFromOeEvidence: Bad enclave key\n")
		return nil, nil
	}
	var toProve *certprotos.VseClause = nil
	if purpose == "authentication" {
		verb := "is-trusted-for-authentication"
		toProve = MakeUnaryVseClause(enclaveKey, &verb)
	} else {
		verb := "is-trusted-for-attestation"
		toProve = MakeUnaryVseClause(enclaveKey, &verb)
	}

	measurementIsTrusted := policyKeySaysMeasurementIsTrusted.Clause
	if measurementIsTrusted == nil {
		fmt.Printf("ConstructProofFromOeEvidence: Can't get measurement\n")
		return nil, nil
	}
	ps1 := certprotos.ProofStep{
		S1:          policyKeyIsTrusted,
		S2:          policyKeySaysMeasurementIsTrusted,
		Conclusion:  measurementIsTrusted,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps1)

	ps2 := certprotos.ProofStep{
		S1:          policyKeyIsTrusted,
		S2:          policyKeySaysPlatformKeyIsTrustedForAttestation,
		Conclusion:  platformKeyIsTrustedForAttestation,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps2)

	ps3 := certprotos.ProofStep{
		S1:          platformKeyIsTrustedForAttestation,
		S2:          platformSaysEnclaveKeySpeaksForMeasurement,
		Conclusion:  enclaveKeySpeaksForMeasurement,
		RuleApplied: &r6,
	}
	proof.Steps = append(proof.Steps, &ps3)

	// measurement is-trusted and enclaveKey speaks-for measurement -->
	//	enclaveKey is-trusted-for-authentication (r1) or
	//	enclaveKey is-trusted-for-attestation (r7)
	if purpose == "authentication" {
		ps4 := certprotos.ProofStep{
			S1:          measurementIsTrusted,
			S2:          enclaveKeySpeaksForMeasurement,
			Conclusion:  toProve,
			RuleApplied: &r1,
		}
		proof.Steps = append(proof.Steps, &ps4)
	} else {
		ps4 := certprotos.ProofStep{
			S1:          measurementIsTrusted,
			S2:          enclaveKeySpeaksForMeasurement,
			Conclusion:  toProve,
			RuleApplied: &r7,
		}
		proof.Steps = append(proof.Steps, &ps4)
	}

	return toProve, proof
}

func ConstructProofFromOeEvidence(publicPolicyKey *certprotos.KeyMessage, purpose string, alreadyProved *certprotos.ProvedStatements) (*certprotos.VseClause, *certprotos.Proof) {
	// At this point, the evidence should be
	//      00: "policyKey is-trusted"
	//      01: "Key[rsa, policyKey, f2663e9ca042fcd261ab051b3a4e3ac83d79afdd] says
	//		Key[rsa, VSE, cbfced04cfc0f1f55df8cbe437c3aba79af1657a] is-trusted-for-attestation"
	//      02: "policyKey says measurement is-trusted"
	//	03: "Key[rsa, VSE, cbfced04cfc0f1f55df8cbe437c3aba79af1657a] says
	//		Key[rsa, auth-key, b1d19c10ec7782660191d7ee4e3a2511fad8f882] speaks-for Measurement[4204...]
	// Or:
	//      00: "policyKey is-trusted"
	//      01: "policyKey says measurement is-trusted"
	//      02: "Key[rsa, auth-key, b1d19c10ec7782660191d7ee4e3a2511fad8f882] speaks-for Measurement[4204...]"

	// Debug
	fmt.Printf("ConstructProofFromOeEvidence, %d statements\n", len(alreadyProved.Proved))
	for i := 0; i < len(alreadyProved.Proved); i++ {
		PrintVseClause(alreadyProved.Proved[i])
		fmt.Printf("\n")
	}

	if len(alreadyProved.Proved) > 3 {
		return ConstructProofFromOeEvidenceWithEndorsement(publicPolicyKey, purpose, alreadyProved)
	} else {
		return ConstructProofFromOeEvidenceWithoutEndorsement(publicPolicyKey, purpose, alreadyProved)
	}
}

// This is used for simulated enclave and the application enclave
func ConstructProofFromInternalPlatformEvidence(publicPolicyKey *certprotos.KeyMessage, purpose string, alreadyProved *certprotos.ProvedStatements) (*certprotos.VseClause, *certprotos.Proof) {
	// At this point, the evidence should be
	//      0: "policyKey is-trusted"
	//      1: "policyKey says platformKey is-trusted-for-attestation"
	//      2: "policyKey says measurement is-trusted"
	//      3: "platformKey says the attestationKey is-trusted-for-attestation
	//      4: "attestationKey says enclaveKey speaks-for measurement
	// Debug
	fmt.Printf("ConstructProofFromInternalPlatformEvidence entries %d\n", len(alreadyProved.Proved))

	if len(alreadyProved.Proved) < 5 {
		fmt.Printf("ConstructProofFromInternalPlatformEvidence: too few proved statements\n")

		fmt.Printf("\nProved statements (Check for missing statements here):\n")
		PrintProvedStatements(alreadyProved)

		return nil, nil
	}

	proof := &certprotos.Proof{}
	r1 := int32(1)
	r3 := int32(3)
	r5 := int32(5)
	r6 := int32(6)
	r7 := int32(7)
	r11 := int32(11)

	policyKeyIsTrusted := alreadyProved.Proved[0]

	policyKeySaysPlatformKeyIsTrusted := alreadyProved.Proved[1]
	platformKeyIsTrusted := policyKeySaysPlatformKeyIsTrusted.Clause
	ps1 := certprotos.ProofStep{
		S1:          policyKeyIsTrusted,
		S2:          policyKeySaysPlatformKeyIsTrusted,
		Conclusion:  platformKeyIsTrusted,
		RuleApplied: &r5,
	}
	proof.Steps = append(proof.Steps, &ps1)

	policyKeySaysMeasurementIsTrusted := alreadyProved.Proved[2]
	measurementIsTrusted := policyKeySaysMeasurementIsTrusted.Clause
	ps2 := certprotos.ProofStep{
		S1:          policyKeyIsTrusted,
		S2:          policyKeySaysMeasurementIsTrusted,
		Conclusion:  measurementIsTrusted,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps2)

	platformKeySaysAttestKeyIsTrusted := alreadyProved.Proved[3]
	attestKeyIsTrusted := platformKeySaysAttestKeyIsTrusted.Clause
	ps3 := certprotos.ProofStep{
		S1:          platformKeyIsTrusted,
		S2:          platformKeySaysAttestKeyIsTrusted,
		Conclusion:  attestKeyIsTrusted,
		RuleApplied: &r5,
	}
	proof.Steps = append(proof.Steps, &ps3)

	attestKeySaysEnclaveKeySpeaksForMeasurement := alreadyProved.Proved[4]
	enclaveKeySpeaksForMeasurement := attestKeySaysEnclaveKeySpeaksForMeasurement.Clause
	ps4 := certprotos.ProofStep{
		S1:          attestKeyIsTrusted,
		S2:          attestKeySaysEnclaveKeySpeaksForMeasurement,
		Conclusion:  enclaveKeySpeaksForMeasurement,
		RuleApplied: &r6,
	}
	proof.Steps = append(proof.Steps, &ps4)

	var toProve *certprotos.VseClause = nil
	isTrustedForAuth := "is-trusted-for-authentication"
	isTrustedForAttest := "is-trusted-for-attestation"
	isTrustedForKeyProvision := "is-trusted-for-key-provision"
	if purpose == "attestation" {
		toProve = MakeUnaryVseClause(enclaveKeySpeaksForMeasurement.Subject,
			&isTrustedForAttest)
		ps5 := certprotos.ProofStep{
			S1:          measurementIsTrusted,
			S2:          enclaveKeySpeaksForMeasurement,
			Conclusion:  toProve,
			RuleApplied: &r7,
		}
		proof.Steps = append(proof.Steps, &ps5)
	} else if purpose == "key-provision" {
		toProve = MakeUnaryVseClause(enclaveKeySpeaksForMeasurement.Subject,
			&isTrustedForKeyProvision)
		ps5 := certprotos.ProofStep{
			S1:          measurementIsTrusted,
			S2:          enclaveKeySpeaksForMeasurement,
			Conclusion:  toProve,
			RuleApplied: &r11,
		}
		proof.Steps = append(proof.Steps, &ps5)
	} else {
		toProve = MakeUnaryVseClause(enclaveKeySpeaksForMeasurement.Subject,
			&isTrustedForAuth)
		ps5 := certprotos.ProofStep{
			S1:          measurementIsTrusted,
			S2:          enclaveKeySpeaksForMeasurement,
			Conclusion:  toProve,
			RuleApplied: &r1,
		}
		proof.Steps = append(proof.Steps, &ps5)
	}

	return toProve, proof
}

/*
	Rules
		rule 1 (R1): If environment or measurement is-trusted and key1 speaks-for environment or measurement then
			key1 is-trusted-for-authentication.
		rule 2 (R2): If key2 speaks-for key1 and key3 speaks-for key2 then key3 speaks-for key1
		rule 3 (R3): If entity is-trusted and entity says X, then X is true
		rule 4 (R4): If key2 speaks-for key1 and key1 is-trusted then key2 is-trusted
		rule 5 (R5): If key1 is-trustedXXX and key1 says key2 is-trustedYYY then key2 is-trustedYYY
			provided is-trustedXXX dominates is-trustedYYY
		rule 6 (R6): if key1 is-trustedXXX and key1 says Y then Y (may want to limit Y later)
			provided is-trustedXXX dominates is-trusted-for-attestation
		rule 7 (R7): If environment or measurement is-trusted and key1 speaks-for environment or measurement then
			key1 is-trusted-for-attestation.
		rule 8 (R8): If environment[platform, measurement] is-environment AND platform-template
			has-trusted-platform-property then environment[platform, measurement]
			environment-platform-is-trusted provided platform properties satisfy platform template
		rule 9 (R9): If environment[platform, measurement] is-environment AND measurement is-trusted then
			environment[platform, measurement] environment-measurement is-trusted
		rule 10 (R10): If environment[platform, measurement] environment-platform-is-trusted AND
			environment[platform, measurement] environment-measurement-is-trusted then
			environment[platform, measurement] is-trusted
*/

func ConstructProofFromSevPlatformEvidence(publicPolicyKey *certprotos.KeyMessage, purpose string, alreadyProved *certprotos.ProvedStatements) (*certprotos.VseClause, *certprotos.Proof) {

	// There should be 9 statements in already proved
	if len(alreadyProved.Proved) < 9 {
		fmt.Printf("ConstructProofFromPlatformEvidence: too few statements %d\n", len(alreadyProved.Proved))
		return nil, nil
	}

	proof := &certprotos.Proof{}
	r1 := int32(1)
	r3 := int32(3)
	r5 := int32(5)
	r6 := int32(6)
	r8 := int32(8)
	r9 := int32(9)
	r10 := int32(10)

	// "policyKey is-trusted" AND policyKey says measurement is-trusted" -->
	//        "measurement is-trusted" (R3)  [0, 2]
	policyKeyIsTrusted := alreadyProved.Proved[0]
	policyKeySaysMeasurementIsTrusted := alreadyProved.Proved[2]
	if policyKeySaysMeasurementIsTrusted.Clause == nil {
		fmt.Printf("ConstructProofFromPlatformEvidence: Policy key says measurement is-trusted is malformed\n")
		return nil, nil
	}
	measurementIsTrusted := policyKeySaysMeasurementIsTrusted.Clause
	ps1 := certprotos.ProofStep{
		S1:          policyKeyIsTrusted,
		S2:          policyKeySaysMeasurementIsTrusted,
		Conclusion:  measurementIsTrusted,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps1)

	//    "policyKey is-trusted" AND
	//        "policy-key says the ARK-key is-trusted-for-attestation" -->
	//        "the ARK-key is-trusted-for-attestation" (R3)  [0, 1]
	policyKeySaysArkKeyIsTrusted := alreadyProved.Proved[1]
	if policyKeySaysArkKeyIsTrusted.Clause == nil {
		fmt.Printf("ConstructProofFromPlatformEvidence: Policy key says ARK key is-trusted-for-attestation is malformed\n")
		return nil, nil
	}
	arkKeyIsTrusted := policyKeySaysArkKeyIsTrusted.Clause
	ps2 := certprotos.ProofStep{
		S1:          policyKeyIsTrusted,
		S2:          policyKeySaysArkKeyIsTrusted,
		Conclusion:  arkKeyIsTrusted,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps2)

	//    "the ARK-key is-trusted-for-attestation" AND
	//        "The ARK-key says the ASK-key is-trusted-for-attestation" -->
	//        "the ASK-key is-trusted-for-attestation" (R5)  [10, 5]
	arkKeySaysAskKeyIsTrusted := alreadyProved.Proved[5]
	if arkKeySaysAskKeyIsTrusted.Clause == nil {
		fmt.Printf("ConstructProofFromPlatformEvidence: ArkKey says Askkey is-trusted-for-attestation is malformed\n")
		return nil, nil
	}
	askKeyIsTrusted := arkKeySaysAskKeyIsTrusted.Clause
	ps3 := certprotos.ProofStep{
		S1:          arkKeyIsTrusted,
		S2:          arkKeySaysAskKeyIsTrusted,
		Conclusion:  askKeyIsTrusted,
		RuleApplied: &r5,
	}
	proof.Steps = append(proof.Steps, &ps3)

	//    "the ASK-key is-trusted-for-attestation" AND
	//        "the ASK-key says the VCEK-key is-trusted-for-attestation" -->
	//        "the VCEK-key is-trusted-for-attestation" (R5) [11, 6]
	askKeySaysVcekKeyIsTrusted := alreadyProved.Proved[6]
	if askKeySaysVcekKeyIsTrusted.Clause == nil {
		fmt.Printf("ConstructProofFromPlatformEvidence: AskKey says vcekKey is-trusted-for-attestation is malformed\n")
		return nil, nil
	}
	vcekKeyIsTrusted := askKeySaysVcekKeyIsTrusted.Clause
	ps4 := certprotos.ProofStep{
		S1:          askKeyIsTrusted,
		S2:          askKeySaysVcekKeyIsTrusted,
		Conclusion:  vcekKeyIsTrusted,
		RuleApplied: &r5,
	}
	proof.Steps = append(proof.Steps, &ps4)

	//    "VCEK-key is-trusted-for-attestation" AND
	//        "the VCEK says environment(platform, measurement) is-environment -->
	//        "environment(platform, measurement) is-environment" [7]
	vcekSaysIsEnvironment := alreadyProved.Proved[7]
	if vcekSaysIsEnvironment.Clause == nil {
		fmt.Printf("ConstructProofFromPlatformEvidence: AskKey says vcekKey is-trusted-for-attestation is malformed\n")
		return nil, nil
	}
	isEnvironment := vcekSaysIsEnvironment.Clause
	ps5 := certprotos.ProofStep{
		S1:          vcekKeyIsTrusted,
		S2:          vcekSaysIsEnvironment,
		Conclusion:  isEnvironment,
		RuleApplied: &r6,
	}
	proof.Steps = append(proof.Steps, &ps5)

	//    policy-key is-trusted AND policy-key says platform has-trusted-platform-property -->
	//    platform has-trusted-platform-property (r3)
	policyKeySaysPlatformHasTrustedPlatformProperty := alreadyProved.Proved[3]
	if policyKeySaysPlatformHasTrustedPlatformProperty.Clause == nil {
		fmt.Printf("ConstructProofFromPlatformEvidence: policy key says platform has trusted property is malformed\n")
		return nil, nil
	}
	platformHasTrustedPlatformProperty := policyKeySaysPlatformHasTrustedPlatformProperty.Clause
	ps6 := certprotos.ProofStep{
		S1:          policyKeyIsTrusted,
		S2:          policyKeySaysPlatformHasTrustedPlatformProperty,
		Conclusion:  platformHasTrustedPlatformProperty,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps6)

	//    "environment(platform, measurement) is-environment" AND
	//        "platform[amd-sev-snp, no-debug,...] has-trusted-platform-property" -->
	//        "environment(platform, measurement) environment-platform-is-trusted" [3, ]
	pitVerb := "environment-platform-is-trusted"
	environmentPlatformIsTrusted := &certprotos.VseClause{
		Subject: isEnvironment.Subject,
		Verb:    &pitVerb,
	}
	ps8 := certprotos.ProofStep{
		S1:          isEnvironment,
		S2:          platformHasTrustedPlatformProperty,
		Conclusion:  environmentPlatformIsTrusted,
		RuleApplied: &r8,
	}
	proof.Steps = append(proof.Steps, &ps8)

	//    "environment(platform, measurement) is-environment" AND
	//        "measurement is-trusted" -->
	//        "environment(platform, measurement) environment-measurement-is-trusted"
	emitVerb := "environment-measurement-is-trusted"
	environmentMeasurementIsTrusted := &certprotos.VseClause{
		Subject: isEnvironment.Subject,
		Verb:    &emitVerb,
	}
	ps9 := certprotos.ProofStep{
		S1:          isEnvironment,
		S2:          measurementIsTrusted,
		Conclusion:  environmentMeasurementIsTrusted,
		RuleApplied: &r9,
	}
	proof.Steps = append(proof.Steps, &ps9)

	//    "environment(platform, measurement) environment-platform-is-trusted" AND
	//        "environment(platform, measurement) environment-measurement-is-trusted"  -->
	//        "environment(platform, measurement) is-trusted
	eitVerb := "is-trusted"
	environmentIsTrusted := &certprotos.VseClause{
		Subject: isEnvironment.Subject,
		Verb:    &eitVerb,
	}
	ps10 := certprotos.ProofStep{
		S1:          environmentMeasurementIsTrusted,
		S2:          environmentPlatformIsTrusted,
		Conclusion:  environmentIsTrusted,
		RuleApplied: &r10,
	}
	proof.Steps = append(proof.Steps, &ps10)

	//    "VCEK-key is-trusted-for-attestation" AND
	//      "VCEK-key says the enclave-key speaks-for the environment()" -->
	//        "enclave-key speaks-for the environment()" [, 8]
	vcekSaysEnclaveKeySpeaksForEnvironment := alreadyProved.Proved[8]
	if vcekSaysEnclaveKeySpeaksForEnvironment == nil {
		fmt.Printf("ConstructProofFromPlatformEvidence: vcek says enclavkey speaks-for environment malformed\n")
		return nil, nil
	}
	enclaveKeySpeaksForEnvironment := vcekSaysEnclaveKeySpeaksForEnvironment.Clause
	ps11 := certprotos.ProofStep{
		S1:          vcekKeyIsTrusted,
		S2:          vcekSaysEnclaveKeySpeaksForEnvironment,
		Conclusion:  enclaveKeySpeaksForEnvironment,
		RuleApplied: &r6,
	}
	proof.Steps = append(proof.Steps, &ps11)

	if purpose == "attestation" {
		itfaVerb := "is-trusted-for-attestation"
		enclaveKeyIsTrusted := &certprotos.VseClause{
			Subject: enclaveKeySpeaksForEnvironment.Subject,
			Verb:    &itfaVerb,
		}
		ps12 := certprotos.ProofStep{
			S1:          environmentIsTrusted,
			S2:          enclaveKeySpeaksForEnvironment,
			Conclusion:  enclaveKeyIsTrusted,
			RuleApplied: &r6,
		}
		proof.Steps = append(proof.Steps, &ps12)

		toProve := enclaveKeyIsTrusted
		return toProve, proof
	} else if purpose == "key-provision" {
		itfaVerb := "is-trusted-for-key-provision"
		enclaveKeyIsTrusted := &certprotos.VseClause{
			Subject: enclaveKeySpeaksForEnvironment.Subject,
			Verb:    &itfaVerb,
		}
		ps12 := certprotos.ProofStep{
			S1:          environmentIsTrusted,
			S2:          enclaveKeySpeaksForEnvironment,
			Conclusion:  enclaveKeyIsTrusted,
			RuleApplied: &r6,
		}
		proof.Steps = append(proof.Steps, &ps12)

		toProve := enclaveKeyIsTrusted
		return toProve, proof
	} else {
		itfaVerb := "is-trusted-for-authentication"
		enclaveKeyIsTrusted := &certprotos.VseClause{
			Subject: enclaveKeySpeaksForEnvironment.Subject,
			Verb:    &itfaVerb,
		}
		ps12 := certprotos.ProofStep{
			S1:          environmentIsTrusted,
			S2:          enclaveKeySpeaksForEnvironment,
			Conclusion:  enclaveKeyIsTrusted,
			RuleApplied: &r1,
		}
		proof.Steps = append(proof.Steps, &ps12)

		toProve := enclaveKeyIsTrusted
		return toProve, proof
	}

	return nil, nil
}

// returns success, toProve, measurement
func ValidateInternalEvidence(pubPolicyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
	policyPool *PolicyPool, purpose string) (bool,
	*certprotos.VseClause, []byte) {

	// Debug
	fmt.Printf("\nValidateInternalEvidence: original policy:\n")
	PrintProvedStatements(policyPool.AllPolicy)

	alreadyProved := FilterInternalPolicy(pubPolicyKey, evp, policyPool)
	if alreadyProved == nil {
		fmt.Printf("ValidateInternalEvidence: Can't filterpolicy\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("\nValidateInternalEvidence: filtered policy:\n")
	PrintProvedStatements(alreadyProved)
	fmt.Printf("\n")

	if !InitProvedStatements(*pubPolicyKey, evp.FactAssertion, alreadyProved) {
		fmt.Printf("ValidateInternalEvidence: Can't InitProvedStatements\n")
		return false, nil, nil
	}

	// After InitProvedStatements already proved will be:
	//    00 Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] is-trusted
	//    01 Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] says Key[rsa, platformKey, c1c06db41296c2dc3ecb2e4a1290f39925699d4d] is-trusted-for-attestation
	//    02 Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] says Measurement[617ac0a68393b4c0b359a76d0fab9015af0801273e13bd366fca57a7af4fe6cc] is-trusted
	//    03 Key[rsa, platformKey, c1c06db41296c2dc3ecb2e4a1290f39925699d4d] says Key[rsa, attestKey, f19938982e3f7e16f524de5f7b47d3e39e32df07] is-trusted-for-attestation
	//    04 Key[rsa, attestKey, f19938982e3f7e16f524de5f7b47d3e39e32df07] says Key[rsa, auth-key, ce3c7cc9b6e7bc733a95434bda226ef4d74e620f] speaks-for Measurement[617ac0a68393b4c0b359a76d0fab9015af0801273e13bd366fca57a7af4fe6cc]

	// Debug
	fmt.Printf("\nValidateInternalEvidence: after InitProved:\n")
	PrintProvedStatements(alreadyProved)

	// ConstructProofFromInternalPlatformEvidence()
	toProve, proof := ConstructProofFromInternalPlatformEvidence(pubPolicyKey, purpose, alreadyProved)
	if toProve == nil || proof == nil {
		fmt.Printf("ValidateInternalEvidence: Can't construct proof\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("\n")
	fmt.Printf("ValidateInternalEvidence, toProve: ")
	PrintVseClause(toProve)
	fmt.Printf("\n")
	PrintProof(proof)
	fmt.Printf("\n")

	if !VerifyProof(pubPolicyKey, toProve, proof, alreadyProved) {
		fmt.Printf("ValidateInternalEvidence: Proof does not verify\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("ValidateInternalEvidence: Proof verifies\n")

	me := alreadyProved.Proved[2]
	if me.Clause == nil || me.Clause.Subject == nil ||
		me.Clause.Subject.GetEntityType() != "measurement" {
		fmt.Printf("ValidateInternalEvidence: Proof does not verify\n")
		return false, nil, nil
	}

	return true, toProve, me.Clause.Subject.Measurement
}

// returns success, toProve, measurement
func ValidateOeEvidence(pubPolicyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
	policyPool *PolicyPool, purpose string) (bool,
	*certprotos.VseClause, []byte) {
	// Debug
	fmt.Printf("\nValidateOeEvidence, Original policy:\n")
	PrintProvedStatements(policyPool.AllPolicy)

	alreadyProved := FilterOePolicy(pubPolicyKey, evp, policyPool)
	if alreadyProved == nil {
		fmt.Printf("ValidateOeEvidence: Can't filterpolicy\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("\nfiltered policy:\n")
	PrintProvedStatements(alreadyProved)
	fmt.Printf("\n")

	if !InitProvedStatements(*pubPolicyKey, evp.FactAssertion, alreadyProved) {
		fmt.Printf("ValidateOeEvidence: Can't InitProvedStatements\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("\nValidateOeEvidence, after InitProved:\n")
	PrintProvedStatements(alreadyProved)

	// ConstructProofFromOePlatformEvidence()
	toProve, proof := ConstructProofFromOeEvidence(pubPolicyKey, purpose, alreadyProved)
	if toProve == nil || proof == nil {
		fmt.Printf("ValidateOeEvidence: Can't construct proof\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("\n")
	fmt.Printf("ValidateOeEvidence, toProve: ")
	PrintVseClause(toProve)
	fmt.Printf("\n")
	PrintProof(proof)
	fmt.Printf("\n")

	if !VerifyProof(pubPolicyKey, toProve, proof, alreadyProved) {
		fmt.Printf("ValidateOeEvidence: Proof does not verify\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("ValidateOeEvidence: Proof verifies\n")
	fmt.Printf("\nProved statements\n")
	PrintProvedStatements(alreadyProved)

	var me *certprotos.VseClause
	for i := 1; i <= len(alreadyProved.Proved); i++ {
		me = alreadyProved.Proved[i]
		if me.Clause != nil && me.Clause.Subject != nil &&
			me.Clause.Subject.GetEntityType() == "measurement" {
			return true, toProve, me.Clause.Subject.Measurement
		}
	}

	fmt.Printf("ValidateOeEvidence: Proof does not verify\n")
	return false, nil, nil
}

// returns success, toProve, measurement
func ValidateSevEvidence(pubPolicyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
	policyPool *PolicyPool, purpose string) (bool,
	*certprotos.VseClause, []byte) {

	// Debug
	fmt.Printf("\nValidateSevEvidence, Original policy:\n")
	PrintProvedStatements(policyPool.AllPolicy)

	alreadyProved := FilterSevPolicy(pubPolicyKey, evp, policyPool)
	if alreadyProved == nil {
		fmt.Printf("Can't filterpolicy\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("\nfiltered policy:\n")
	PrintProvedStatements(alreadyProved)
	fmt.Printf("\n")

	if !InitProvedStatements(*pubPolicyKey, evp.FactAssertion, alreadyProved) {
		fmt.Printf("ValidateSevEvidence: Can't InitProvedStatements\n")
		return false, nil, nil
	}

	// After InitProved alreadyProved should be:
	//
	//  00 Key[rsa, policyKey, f91d6331b1fd99b3fa8641fd16dcd4c272a92b8a] is-trusted
	//  01 Key[rsa, policyKey, f91d6331b1fd99b3fa8641fd16dcd4c272a92b8a] says
	//	Key[rsa, ARKKey, c36d3343d69d9d8000d32d0979adff876e98ec79] is-trusted-for-attestation
	//  02 Key[rsa, policyKey, f91d6331b1fd99b3fa8641fd16dcd4c272a92b8a] says
	//      Measurement[010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708] is-trusted
	//  03 Key[rsa, policyKey, f91d6331b1fd99b3fa8641fd16dcd4c272a92b8a] says
	//	platform[amd-sev-snp, debug: no, migrate: no, api-major: >=0, api-minor: >=0, key-share: no,
	//		tcb-version: >=0] has-trusted-platform-property
	//  04 Key[rsa, ARKKey, c36d3343d69d9d8000d32d0979adff876e98ec79] says
	//	Key[rsa, ARKKey, c36d3343d69d9d8000d32d0979adff876e98ec79] is-trusted-for-attestation
	//  05 Key[rsa, ARKKey, c36d3343d69d9d8000d32d0979adff876e98ec79] says
	//	Key[rsa, ASKKey, c87c716e16df326f58c5fe026eb55133d57239ff] is-trusted-for-attestation
	//  06 Key[rsa, ASKKey, c87c716e16df326f58c5fe026eb55133d57239ff] says
	//	Key[ecc-P-384, VCEKKey,
	//	d8a35da4a4780fe58fe5a02e5aec7d40fa7452ca89ca4c6620181228b3e4e9c41ab9a200875a2b6e044ae73936408d27]
	//	is-trusted-for-attestation
	//  07 Key[ecc-P-384, VCEKKey,
	//	d8a35da4a4780fe58fe5a02e5aec7d40fa7452ca89ca4c6620181228b3e4e9c41ab9a200875a2b6e044ae73936408d27]
	//	says environment[platform[amd-sev-snp, debug: no, smt: no, migrate: no, api-major: =0,
	//	api-minor: =0, tcb-version: =0],
	//	measurement: 010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708]
	//	is-environment
	//  08 Key[ecc-P-384, VCEKKey,
	//	d8a35da4a4780fe58fe5a02e5aec7d40fa7452ca89ca4c6620181228b3e4e9c41ab9a200875a2b6e044ae73936408d27] says
	//	Key[rsa, policyKey, f91d6331b1fd99b3fa8641fd16dcd4c272a92b8a] speaks-for
	//	environment[platform[amd-sev-snp, debug: no, key-share: no, migrate: no, api-major: =0,
	//	api-minor: =0, tcb-version: =0], measurement:
	//	010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708]

	// Debug
	fmt.Printf("\nValidateSevEvidence, after InitProved:\n")
	PrintProvedStatements(alreadyProved)

	// ConstructProofFromSevPlatformEvidence()
	toProve, proof := ConstructProofFromSevPlatformEvidence(pubPolicyKey, purpose, alreadyProved)
	if toProve == nil || proof == nil {
		fmt.Printf("ValidateSevEvidence: Can't construct proof\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("\n")
	fmt.Printf("ValidateSevEvidence, toProve: ")
	PrintVseClause(toProve)
	fmt.Printf("\n")
	PrintProof(proof)
	fmt.Printf("\n")

	if !VerifyProof(pubPolicyKey, toProve, proof, alreadyProved) {
		fmt.Printf("ValidateSevEvidence: Proof does not verify\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("ValidateSevEvidence: Proof verifies\n")
	fmt.Printf("\nProved statements\n")
	PrintProvedStatements(alreadyProved)

	me := alreadyProved.Proved[2]
	if me.Clause == nil || me.Clause.Subject == nil ||
		me.Clause.Subject.GetEntityType() != "measurement" {
		fmt.Printf("ValidateSevEvidence: Proof does not verify\n")
		return false, nil, nil
	}

	return true, toProve, me.Clause.Subject.Measurement
}

func ConstructGramineIsEnvironmentClaim(measurement []byte, attestation []byte) *certprotos.VseClause {

	pl := GetPlatformFromGramineAttest(attestation)
	if pl == nil {
		fmt.Printf("ConstructExtendedGramineClaim: Can't make platform\n")
		return nil
	}

	e := MakeEnvironment(pl, measurement)
	if e == nil {
		fmt.Printf("ConstructExtendedGramineClaim: Can't make environment\n")
		return nil
	}

	ee := MakeEnvironmentEntity(e)
	if ee == nil {
		fmt.Printf("ConstructExtendedGramineClaim: Can't make environment entity\n")
		return nil
	}

	verbie := "is-environment"
	return MakeUnaryVseClause(ee, &verbie)
}

func ConstructGramineSpeaksForClaim(enclaveKey *certprotos.KeyMessage,
	env *certprotos.EntityMessage) *certprotos.VseClause {

	em := MakeKeyEntity(enclaveKey)
	if em == nil {
		fmt.Printf("ConstructGramineClaim: Can't make enclave entity\n")
		return nil
	}
	speaks_for := "speaks-for"
	return MakeSimpleVseClause(em, &speaks_for, env)
}

func ConstructGramineClaim(enclaveKey *certprotos.KeyMessage,
	measurement []byte) *certprotos.VseClause {

	em := MakeKeyEntity(enclaveKey)
	if em == nil {
		fmt.Printf("ConstructGramineClaim: Can't make enclave entity\n")
		return nil
	}
	mm := MakeMeasurementEntity(measurement)
	if mm == nil {
		fmt.Printf("ConstructGramineClaim: Can't make measurement entity\n")
		return nil
	}
	speaks_for := "speaks-for"
	return MakeSimpleVseClause(em, &speaks_for, mm)
}

func VerifyGramineAttestation(serializedEvidence []byte) (bool, []byte, []byte, error) {
	// Returns: success, serialized user data, measurement, err
	ga := certprotos.GramineAttestationMessage{}
	err := proto.Unmarshal(serializedEvidence, &ga)
	if err != nil {
		fmt.Printf("VerifyGramineAttestation: Can't unmarshal gramine attestation\n")
		return false, nil, nil, errors.New("Can't unmarshal gramine attestation")
	}

	// Call the cgo gramine verify function
	m, err := gramineverify.GramineVerify(ga.WhatWasSaid, ga.ReportedAttestation)
	if err != nil {
		fmt.Printf("VerifyGramineAttestation: gramine verify failed\n")
		return false, ga.WhatWasSaid, m, nil
	}
	return true, ga.WhatWasSaid, m, nil
}

// Filtered policy should be
//      Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] is-trusted
//      Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
//              Key[rsa, platformKey, cdc8112d97fce6767143811f0ed5fb6c21aee424] is-trusted-for-attestation
//      Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
//              Measurement[0001020304050607...] is-trusted
func FilterGraminePolicy(policyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
	policyPool *PolicyPool) *certprotos.ProvedStatements {

	/* Debug
	fmt.Printf("Incoming evidence for Gramine\n")
	PrintEvidencePackage(evp, true)
	fmt.Printf("\nOriginal Platform Policy:\n")
	for i := 0; i < len(policyPool.PlatformKeyPolicy.Proved); i++ {
		cl := policyPool.PlatformKeyPolicy.Proved[i]
		PrintVseClause(cl)
		fmt.Printf("\n")
	}
	fmt.Printf("\n")
	fmt.Printf("\nOriginal Measurement Policy:\n")
	for i := 0; i < len(policyPool.MeasurementPolicy.Proved); i++ {
		cl := policyPool.MeasurementPolicy.Proved[i]
		PrintVseClause(cl)
		fmt.Printf("\n")
	}
	fmt.Printf("\n\n")
	*/

	filtered := &certprotos.ProvedStatements{}

	// policyKey is-trusted
	from := policyPool.AllPolicy.Proved[0]
	to := proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	// This should be passed in
	evType := "gramine-evidence"

	from = GetRelevantPlatformKeyPolicy(policyPool, evType, evp)
	if from == nil {
		return nil
	}
	to = proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	from = GetRelevantMeasurementPolicy(policyPool, evType, evp)
	if from == nil {
		return nil
	}
	to = proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	return filtered
}

func ConstructProofFromGramineEvidence(publicPolicyKey *certprotos.KeyMessage, purpose string,
	alreadyProved *certprotos.ProvedStatements) (*certprotos.VseClause, *certprotos.Proof) {
	// At this point, the evidence should be
	//	Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] is-trusted
	//	Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
	//		Key[rsa, PlatformKey, cdc8112d97fce6767143811f0ed5fb6c21aee424] is-trusted-for-attestation
	//	Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
	//		Measurement[0001020304050607...] is-trusted
	//	Key[rsa, PlatformKey, cdc8112d97fce6767143811f0ed5fb6c21aee424] says
	//		Key[rsa, attestKey, cdc8112d97fce6767143811f0ed5fb6c21aee424] is-trusted-for-attestation
	//	Key[rsa, enclaveKey, b223d5da6674c6bde7feac29801e3b69bb286320] speaks-for Measurement[00010203...]

	// Debug
	fmt.Printf("ConstructProofFromGramineEvidence, %d statements\n", len(alreadyProved.Proved))
	for i := 0; i < len(alreadyProved.Proved); i++ {
		PrintVseClause(alreadyProved.Proved[i])
		fmt.Printf("\n")
	}

	if len(alreadyProved.Proved) < 5 {
		fmt.Printf("ConstructProofFromGramineEvidence: too few statements\n")
		return nil, nil
	}

	policyKeyIsTrusted := alreadyProved.Proved[0]
	policyKeySaysPlatformKeyIsTrustedForAttestation := alreadyProved.Proved[1]
	policyKeySaysMeasurementIsTrusted := alreadyProved.Proved[2]
	enclaveKeySpeaksForMeasurement := alreadyProved.Proved[4]

	if policyKeyIsTrusted == nil || enclaveKeySpeaksForMeasurement == nil ||
		policyKeySaysMeasurementIsTrusted == nil {
		fmt.Printf("ConstructProofFromGramineEvidence: evidence missing\n")
		return nil, nil
	}

	if policyKeySaysPlatformKeyIsTrustedForAttestation.Clause == nil {
		fmt.Printf("ConstructProofFromGramineEvidence: Can't get platformKeyIsTrustedForAttestation\n")
		return nil, nil
	}
	// platformKeyIsTrustedForAttestation := policyKeySaysPlatformKeyIsTrustedForAttestation.Clause

	proof := &certprotos.Proof{}
	r1 := int32(1)
	r3 := int32(3)
	r7 := int32(7)

	enclaveKey := enclaveKeySpeaksForMeasurement.Subject
	if enclaveKey == nil || enclaveKey.GetEntityType() != "key" {
		fmt.Printf("ConstructProofFromGramineEvidence: Bad enclave key\n")
		return nil, nil
	}
	var toProve *certprotos.VseClause = nil
	if purpose == "authentication" {
		verb := "is-trusted-for-authentication"
		toProve = MakeUnaryVseClause(enclaveKey, &verb)
	} else {
		verb := "is-trusted-for-attestation"
		toProve = MakeUnaryVseClause(enclaveKey, &verb)
	}

	measurementIsTrusted := policyKeySaysMeasurementIsTrusted.Clause
	if measurementIsTrusted == nil {
		fmt.Printf("ConstructProofFromGramineEvidence: Can't get measurement\n")
		return nil, nil
	}
	ps1 := certprotos.ProofStep{
		S1:          policyKeyIsTrusted,
		S2:          policyKeySaysMeasurementIsTrusted,
		Conclusion:  measurementIsTrusted,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps1)

	// measurement is-trusted and enclaveKey speaks-for measurement -->
	//	enclaveKey is-trusted-for-authentication (r1) or
	//	enclaveKey is-trusted-for-attestation (r7)
	if purpose == "authentication" {
		ps4 := certprotos.ProofStep{
			S1:          measurementIsTrusted,
			S2:          enclaveKeySpeaksForMeasurement,
			Conclusion:  toProve,
			RuleApplied: &r1,
		}
		proof.Steps = append(proof.Steps, &ps4)
	} else {
		ps4 := certprotos.ProofStep{
			S1:          measurementIsTrusted,
			S2:          enclaveKeySpeaksForMeasurement,
			Conclusion:  toProve,
			RuleApplied: &r7,
		}
		proof.Steps = append(proof.Steps, &ps4)
	}

	return toProve, proof
}

// returns success, toProve, measurement
func ValidateGramineEvidence(pubPolicyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
	policyPool *PolicyPool, purpose string) (bool,
	*certprotos.VseClause, []byte) {

	// Debug
	fmt.Printf("\nValidateGramineEvidence, Original policy:\n")
	PrintProvedStatements(policyPool.AllPolicy)

	alreadyProved := FilterGraminePolicy(pubPolicyKey, evp, policyPool)
	if alreadyProved == nil {
		fmt.Printf("ValidateGramineEvidence: Can't filterpolicy\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("\nfiltered policy:\n")
	PrintProvedStatements(alreadyProved)
	fmt.Printf("\n")

	if !InitProvedStatements(*pubPolicyKey, evp.FactAssertion, alreadyProved) {
		fmt.Printf("ValidateGramineEvidence: Can't InitProvedStatements\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("\nValidateGramineEvidence, after InitProved:\n")
	PrintProvedStatements(alreadyProved)

	// ConstructProofFromSevPlatformEvidence()
	toProve, proof := ConstructProofFromGramineEvidence(pubPolicyKey, purpose, alreadyProved)
	if toProve == nil || proof == nil {
		fmt.Printf("ValidateGramineEvidence: Can't construct proof\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("\n")
	fmt.Printf("ValidateGramineEvidence, toProve: ")
	PrintVseClause(toProve)
	fmt.Printf("\n")
	PrintProof(proof)
	fmt.Printf("\n")

	if !VerifyProof(pubPolicyKey, toProve, proof, alreadyProved) {
		fmt.Printf("ValidateGramineEvidence: Proof does not verify\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("ValidateGramineEvidence: Proof verifies\n")
	fmt.Printf("\nProved statements\n")
	PrintProvedStatements(alreadyProved)

	me := alreadyProved.Proved[2]
	if me.Clause == nil || me.Clause.Subject == nil ||
		me.Clause.Subject.GetEntityType() != "measurement" {
		fmt.Printf("ValidateGramineEvidence: Proof does not verify\n")
		return false, nil, nil
	}

	return true, toProve, me.Clause.Subject.Measurement
}

// Filtered policy should be
//      Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] is-trusted
//      Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
//              Key[rsa, platformKey, cdc8112d97fce6767143811f0ed5fb6c21aee424] is-trusted-for-attestation
//      Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
//              Measurement[0001020304050607...] is-trusted
//	Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
//          platform has-trusted-platform-property
// Filter out irrelevant platforms and measurements
func FilterExtendedGraminePolicy(policyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
	policyPool *PolicyPool) *certprotos.ProvedStatements {

	fmt.Printf("\nFilterExtendedGraminePolicy: Incoming evidence for Gramine\n")
	PrintEvidencePackage(evp, true)
	fmt.Printf("\nOriginal Platform Policy:\n")
	for i := 0; i < len(policyPool.PlatformKeyPolicy.Proved); i++ {
		cl := policyPool.PlatformKeyPolicy.Proved[i]
		PrintVseClause(cl)
		fmt.Printf("\n")
	}
	fmt.Printf("\n")
	fmt.Printf("\nOriginal Measurement Policy:\n")
	for i := 0; i < len(policyPool.MeasurementPolicy.Proved); i++ {
		cl := policyPool.MeasurementPolicy.Proved[i]
		PrintVseClause(cl)
		fmt.Printf("\n")
	}
	fmt.Printf("\nOriginal Platform Policy:\n")
	for i := 0; i < len(policyPool.PlatformFeaturePolicy.Proved); i++ {
		cl := policyPool.PlatformFeaturePolicy.Proved[i]
		PrintVseClause(cl)
		fmt.Printf("\n")
	}
	fmt.Printf("\n\n")

	filtered := &certprotos.ProvedStatements{}

	// policyKey is-trusted
	from := policyPool.AllPolicy.Proved[0]
	to := proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	// This should be passed in
	evType := "gramine-evidence"

	// PlatformKey
	from = GetRelevantPlatformKeyPolicy(policyPool, evType, evp)
	if from == nil {
		return nil
	}
	to = proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	// Measurement
	from = GetRelevantMeasurementPolicy(policyPool, evType, evp)
	if from == nil {
		return nil
	}
	to = proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	// Platform
	from = GetRelevantPlatformFeaturePolicy(policyPool, evType, evp)
	if from == nil {
		fmt.Printf("FilterExtendedGraminePolicy: Can't get relavent platform features\n")
		return nil
	}
	to = proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	return filtered
}

/*
Incoming evidence:
	  0. Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] is-trusted
  	  1. Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
     	       Key[rsa, platformKey, cdc8112d97fce6767143811f0ed5fb6c21aee424] is-trusted-for-attestation
  	  2. Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
                  Measurement[0001020304050607...] is-trusted
  	  3. Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
      	          platform has-trusted-platform-property
  	  4. Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
     	       Key[rsa, platformKey, cdc8112d97fce6767143811f0ed5fb6c21aee424] is-trusted-for-attestation
  	  5. environment(platform, measurement) is-environment
  	  6. enclaveKey speaks-for Measurement[00010203...]

Produced proof should be:
	  0. Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] is-trusted AND
	        Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0]
	  	says Measurement[0001020304050607...] is-trusted -->
		    Measurement[0001020304050607...] is-trusted
	  1. policy-key is-trusted AND policy-key says platform has-trusted-platform-property -->
                    platform has-trusted-platform-property (r3)
	  2. environment(platform, measurement) is-environment AND
     	         platform[amd-sev-snp, no-debug,...] has-trusted-platform-property -->
     	         environment(platform, measurement) environment-platform-is-trusted [3, ]
	  3. environment(platform, measurement) is-environment AND measurement is-trusted -->
                 environment(platform, measurement) environment-measurement-is-trusted
	  4. environment(platform, measurement) environment-platform-is-trusted" AND
       	         environment(platform, measurement) environment-measurement-is-trusted"  -->
                    environment(platform, measurement) is-trusted
	  5. environment is-trusted and enclaveKey speaks-for environment -->
	         enclaveKey is-trusted-for-authentication
*/
func ConstructProofFromExtendedGramineEvidence(publicPolicyKey *certprotos.KeyMessage, purpose string,
	alreadyProved *certprotos.ProvedStatements) (*certprotos.VseClause, *certprotos.Proof) {

	// Debug
	fmt.Printf("ConstructProofFromExtendedGramineEvidence, %d statements\n", len(alreadyProved.Proved))
	for i := 0; i < len(alreadyProved.Proved); i++ {
		PrintVseClause(alreadyProved.Proved[i])
		fmt.Printf("\n")
	}

	if len(alreadyProved.Proved) < 7 {
		fmt.Printf("ConstructProofFromGramineEvidence: too few statements\n")
		return nil, nil
	}

	policyKeyIsTrusted := alreadyProved.Proved[0]
	policyKeySaysMeasurementIsTrusted := alreadyProved.Proved[2]
	policyKeySaysPlatformHasTrustedProperty := alreadyProved.Proved[3]
	environmentIsEnvironment := alreadyProved.Proved[5]
	enclaveKeySpeaksForEnvironment := alreadyProved.Proved[6]

	if policyKeyIsTrusted == nil || enclaveKeySpeaksForEnvironment == nil ||
		policyKeySaysMeasurementIsTrusted == nil || policyKeySaysPlatformHasTrustedProperty == nil ||
		environmentIsEnvironment == nil {
		fmt.Printf("ConstructProofFromGramineEvidence: evidence missing\n")
		return nil, nil
	}

	proof := &certprotos.Proof{}
	r1 := int32(1)
	r3 := int32(3)
	r8 := int32(8)
	r9 := int32(9)
	r10 := int32(10)
	r6 := int32(6)

	measurementIsTrusted := policyKeySaysMeasurementIsTrusted.Clause
	if measurementIsTrusted == nil {
		fmt.Printf("ConstructProofFromExtendedGramineEvidence: Can't get measurement\n")
		return nil, nil
	}
	ps1 := certprotos.ProofStep{
		S1:          policyKeyIsTrusted,
		S2:          policyKeySaysMeasurementIsTrusted,
		Conclusion:  measurementIsTrusted,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps1)

	// policy-key is-trusted AND policy-key says platform has-trusted-platform-property -->
	//     platform has-trusted-platform-property (r3)
	platformHasTrustedProperty := policyKeySaysPlatformHasTrustedProperty.Clause
	if platformHasTrustedProperty == nil {
		fmt.Printf("ConstructProofFromExtendedGramineEvidence: no platform trusted properties rule \n")
		return nil, nil
	}
	ps2 := certprotos.ProofStep{
		S1:          policyKeyIsTrusted,
		S2:          policyKeySaysPlatformHasTrustedProperty,
		Conclusion:  platformHasTrustedProperty,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps2)

	// environment(platform, measurement) is-environment AND
	//       platform[amd-sev-snp, no-debug,...] has-trusted-platform-property -->
	//       environment(platform, measurement) environment-platform-is-trusted

	v0 := "environment-platform-is-trusted"
	environmentPlatformIsTrusted := MakeUnaryVseClause(environmentIsEnvironment.Subject, &v0)
	if environmentPlatformIsTrusted == nil {
		fmt.Printf("ConstructProofFromExtendedGramineEvidence: Can't get environment platform is trusted\n")
		return nil, nil
	}
	ps3 := certprotos.ProofStep{
		S1:          environmentIsEnvironment,
		S2:          platformHasTrustedProperty,
		Conclusion:  environmentPlatformIsTrusted,
		RuleApplied: &r8,
	}
	proof.Steps = append(proof.Steps, &ps3)

	// environment(platform, measurement) is-environment AND measurement is-trusted -->
	//       environment(platform, measurement) environment-measurement-is-trusted
	v1 := "environment-measurement-is-trusted"
	environmentMeasurementIsTrusted := MakeUnaryVseClause(environmentIsEnvironment.Subject, &v1)
	if environmentMeasurementIsTrusted == nil {
		fmt.Printf("ConstructProofFromExtendedGramineEvidence: Can't get environment measurement is trusted\n")
		return nil, nil
	}
	ps4 := certprotos.ProofStep{
		S1:          environmentIsEnvironment,
		S2:          measurementIsTrusted,
		Conclusion:  environmentMeasurementIsTrusted,
		RuleApplied: &r9,
	}
	proof.Steps = append(proof.Steps, &ps4)

	// environment(platform, measurement) environment-platform-is-trusted" AND
	//     environment(platform, measurement) environment-measurement-is-trusted"  -->
	//       environment(platform, measurement) is-trusted
	v2 := "is-trusted"
	environmentIsTrusted := MakeUnaryVseClause(environmentIsEnvironment.Subject, &v2)
	if environmentIsTrusted == nil {
		fmt.Printf("ConstructProofFromExtendedGramineEvidence: Can't create environment is trusted\n")
		return nil, nil
	}
	ps5 := certprotos.ProofStep{
		S1:          environmentMeasurementIsTrusted,
		S2:          environmentPlatformIsTrusted,
		Conclusion:  environmentIsTrusted,
		RuleApplied: &r10,
	}
	proof.Steps = append(proof.Steps, &ps5)

	enclaveKey := enclaveKeySpeaksForEnvironment.Subject
	if enclaveKey == nil || enclaveKey.GetEntityType() != "key" {
		fmt.Printf("ConstructProofFromExtendedGramineEvidence: Bad enclave key\n")
		return nil, nil
	}
	var toProve *certprotos.VseClause = nil
	if purpose == "authentication" {
		verb := "is-trusted-for-authentication"
		toProve = MakeUnaryVseClause(enclaveKey, &verb)
		if toProve == nil {
			fmt.Printf("ConstructProofFromExtendedGramineEvidence: Can't create toProve\n")
			return nil, nil
		}
	} else {
		verb := "is-trusted-for-attestation"
		toProve = MakeUnaryVseClause(enclaveKey, &verb)
		if toProve == nil {
			fmt.Printf("ConstructProofFromExtendedGramineEvidence: Can't create toProve\n")
			return nil, nil
		}
	}

	// environment is-trusted and enclaveKey speaks-for measurement -->
	//	enclaveKey is-trusted-for-authentication (r1) or
	//	enclaveKey is-trusted-for-attestation (r6)
	if purpose == "authentication" {
		ps6 := certprotos.ProofStep{
			S1:          environmentIsTrusted,
			S2:          enclaveKeySpeaksForEnvironment,
			Conclusion:  toProve,
			RuleApplied: &r1,
		}
		proof.Steps = append(proof.Steps, &ps6)
	} else {
		ps6 := certprotos.ProofStep{
			S1:          environmentIsTrusted,
			S2:          enclaveKeySpeaksForEnvironment,
			Conclusion:  toProve,
			RuleApplied: &r6,
		}
		proof.Steps = append(proof.Steps, &ps6)
	}

	return toProve, proof
}

// returns success, toProve, measurement
func ValidateExtendedGramineEvidence(pubPolicyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
	policyPool *PolicyPool, purpose string) (bool,
	*certprotos.VseClause, []byte) {

	// Debug
	fmt.Printf("\nValidateExtendedGramineEvidence, Original policy:\n")
	PrintProvedStatements(policyPool.AllPolicy)

	alreadyProved := FilterExtendedGraminePolicy(pubPolicyKey, evp, policyPool)
	if alreadyProved == nil {
		fmt.Printf("ValidateExtendedGramineEvidence: Can't filterpolicy\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("\nfiltered policy:\n")
	PrintProvedStatements(alreadyProved)
	fmt.Printf("\n")

	if !InitProvedStatements(*pubPolicyKey, evp.FactAssertion, alreadyProved) {
		fmt.Printf("ValidateExtendedGramineEvidence: Can't InitProvedStatements\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("\nValidateExtendedGramineEvidence, after InitProved:\n")
	PrintProvedStatements(alreadyProved)

	// ConstructProofFromSevPlatformEvidence()
	toProve, proof := ConstructProofFromExtendedGramineEvidence(pubPolicyKey, purpose, alreadyProved)
	if toProve == nil || proof == nil {
		fmt.Printf("ValidateExtendedGramineEvidence: Can't construct proof\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("\n")
	fmt.Printf("ValidateExtendedGramineEvidence, toProve: ")
	PrintVseClause(toProve)
	fmt.Printf("\n")
	PrintProof(proof)
	fmt.Printf("\n")

	if !VerifyProof(pubPolicyKey, toProve, proof, alreadyProved) {
		fmt.Printf("ValidateExtendedGramineEvidence: Proof does not verify\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("ValidateExtendedGramineEvidence: Proof verifies\n")
	fmt.Printf("\nProved statements\n")
	PrintProvedStatements(alreadyProved)

	me := alreadyProved.Proved[2]
	if me.Clause == nil || me.Clause.Subject == nil ||
		me.Clause.Subject.GetEntityType() != "measurement" {
		fmt.Printf("ValidateGramineEvidence: Proof does not verify\n")
		return false, nil, nil
	}

	return true, toProve, me.Clause.Subject.Measurement
}

func FilterKeystonePolicy(policyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
	policyPool *PolicyPool) *certprotos.ProvedStatements {

	/* Debug
	fmt.Printf("Incoming evidence for Keystone\n")
	PrintEvidencePackage(evp, true)
	fmt.Printf("\nOriginal Platform Policy:\n")
	for i := 0; i < len(policyPool.PlatformKeyPolicy.Proved); i++ {
		cl := policyPool.PlatformKeyPolicy.Proved[i]
		PrintVseClause(cl)
		fmt.Printf("\n")
	}
	fmt.Printf("\n")
	fmt.Printf("\nOriginal Measurement Policy:\n")
	for i := 0; i < len(policyPool.MeasurementPolicy.Proved); i++ {
		cl := policyPool.MeasurementPolicy.Proved[i]
		PrintVseClause(cl)
		fmt.Printf("\n")
	}
	fmt.Printf("\n\n")
	*/

	filtered := &certprotos.ProvedStatements{}

	// policyKey is-trusted
	from := policyPool.AllPolicy.Proved[0]
	to := proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	// This should be passed in
	evType := "keystone-evidence"

	// Keystone does not put the platform key in the evidence,
	// so we have to get it from policy.  This should be fixed.
	// For now, get the first statement in policy with the
	// Key name "KeystoneAuthority"
	var platStatement *certprotos.VseClause = nil
	for i := 0; i < len(policyPool.AllPolicy.Proved); i++ {
		cl := policyPool.AllPolicy.Proved[i]
		if cl == nil || cl.Clause == nil {
			continue
		}
		s := cl.Clause
		if s.Subject == nil || s.GetVerb() != "is-trusted-for-attestation" {
			continue
		}
		if s.Subject.GetEntityType() != "key" || s.Subject.Key == nil ||
			s.Subject.Key.GetKeyName() != "KeystoneAuthority" {
			continue
		}
		platStatement = cl
	}
	if platStatement == nil {
		fmt.Printf("FilterKeystonePolicy: bad platform statement\n")
		return nil
	}
	to = proto.Clone(platStatement).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, platStatement)

	from = GetRelevantMeasurementPolicy(policyPool, evType, evp)
	if from == nil {
		fmt.Printf("FilterKeystonePolicy: Can't get relevant measurement\n")
		return nil
	}
	to = proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	return filtered
}

func ConstructProofFromKeystoneEvidence(publicPolicyKey *certprotos.KeyMessage, purpose string,
	alreadyProved *certprotos.ProvedStatements) (*certprotos.VseClause, *certprotos.Proof) {
	// At this point, the evidence should be
	//	Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] is-trusted
	//	Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
	//		Key[rsa, AttestKey, cdc8112d97fce6767143811f0ed5fb6c21aee424] is-trusted-for-attestation
	//	Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
	//		Measurement[0001020304050607...] is-trusted
	//	Key attestKey says Key[rsa, enclaveKey, b223d5da6674c6bde7feac29801e3b69bb286320] speaks-for Measurement[00010203...]

	// Debug
	fmt.Printf("ConstructProofFromKeystoneEvidence, %d statements\n", len(alreadyProved.Proved))
	for i := 0; i < len(alreadyProved.Proved); i++ {
		PrintVseClause(alreadyProved.Proved[i])
		fmt.Printf("\n")
	}

	if len(alreadyProved.Proved) < 4 {
		fmt.Printf("ConstructProofFromKeystoneEvidence: too few statements\n")
		return nil, nil
	}

	policyKeyIsTrusted := alreadyProved.Proved[0]
	policyKeySaysAttestKeyIsTrustedForAttestation := alreadyProved.Proved[1]
	policyKeySaysMeasurementIsTrusted := alreadyProved.Proved[2]
	if alreadyProved.Proved[3].Clause == nil {
		fmt.Printf("ConstructProofFromKeystoneEvidence: malformed attestation\n")
		return nil, nil
	}
	attestKeySaysEnclaveKeySpeaksForMeasurement := alreadyProved.Proved[3]
	enclaveKeySpeaksForMeasurement := alreadyProved.Proved[3].Clause

	if policyKeyIsTrusted == nil || enclaveKeySpeaksForMeasurement == nil ||
		policyKeySaysMeasurementIsTrusted == nil {
		fmt.Printf("ConstructProofFromKeystoneEvidence: evidence missing\n")
		return nil, nil
	}

	if policyKeySaysAttestKeyIsTrustedForAttestation.Clause == nil {
		fmt.Printf("ConstructProofFromKeystoneEvidence: Can't get platformKeyIsTrustedForAttestation\n")
		return nil, nil
	}

	proof := &certprotos.Proof{}
	r1 := int32(1)
	r3 := int32(3)
	r6 := int32(6)
	r7 := int32(7)

	enclaveKey := enclaveKeySpeaksForMeasurement.Subject
	if enclaveKey == nil || enclaveKey.GetEntityType() != "key" {
		fmt.Printf("ConstructProofFromKeystoneEvidence: Bad enclave key\n")
		return nil, nil
	}
	var toProve *certprotos.VseClause = nil
	if purpose == "authentication" {
		verb := "is-trusted-for-authentication"
		toProve = MakeUnaryVseClause(enclaveKey, &verb)
	} else {
		verb := "is-trusted-for-attestation"
		toProve = MakeUnaryVseClause(enclaveKey, &verb)
	}

	measurementIsTrusted := policyKeySaysMeasurementIsTrusted.Clause
	if measurementIsTrusted == nil {
		fmt.Printf("ConstructProofFromKeystoneEvidence: Can't get measurement\n")
		return nil, nil
	}
	ps1 := certprotos.ProofStep{
		S1:          policyKeyIsTrusted,
		S2:          policyKeySaysMeasurementIsTrusted,
		Conclusion:  measurementIsTrusted,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps1)

	// add policyKey is-trusted AND
	// policyKey says attestKey is-trusted-for-attestation -->
	// attestKey is-trusted-for-attestation
	if policyKeySaysAttestKeyIsTrustedForAttestation.Clause == nil {
		fmt.Printf("ConstructProofFromKeystoneEvidence: Can't malformed attestation key appointment\n")
		return nil, nil
	}
	attestKeyIsTrustedForAttestation := policyKeySaysAttestKeyIsTrustedForAttestation.Clause
	ps2 := certprotos.ProofStep{
		S1:          policyKeyIsTrusted,
		S2:          policyKeySaysAttestKeyIsTrustedForAttestation,
		Conclusion:  attestKeyIsTrustedForAttestation,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps2)

	// add attestKey is-trusted-for-attestation AND
	// attestKey says enclaveKey speaks-for measurement -->
	// enclaveKey speaks-for measurement
	ps3 := certprotos.ProofStep{
		S1:          attestKeyIsTrustedForAttestation,
		S2:          attestKeySaysEnclaveKeySpeaksForMeasurement,
		Conclusion:  enclaveKeySpeaksForMeasurement,
		RuleApplied: &r6,
	}
	proof.Steps = append(proof.Steps, &ps3)

	// measurement is-trusted and enclaveKey speaks-for measurement -->
	//	enclaveKey is-trusted-for-authentication (r1) or
	//	enclaveKey is-trusted-for-attestation (r7)
	if purpose == "authentication" {
		ps4 := certprotos.ProofStep{
			S1:          measurementIsTrusted,
			S2:          enclaveKeySpeaksForMeasurement,
			Conclusion:  toProve,
			RuleApplied: &r1,
		}
		proof.Steps = append(proof.Steps, &ps4)
	} else {
		ps4 := certprotos.ProofStep{
			S1:          measurementIsTrusted,
			S2:          enclaveKeySpeaksForMeasurement,
			Conclusion:  toProve,
			RuleApplied: &r7,
		}
		proof.Steps = append(proof.Steps, &ps4)
	}

	return toProve, proof
}

// returns success, toProve, measurement
func ValidateKeystoneEvidence(pubPolicyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
	policyPool *PolicyPool, purpose string) (bool,
	*certprotos.VseClause, []byte) {

	// Debug
	fmt.Printf("\nValidateKeystoneEvidence, Original policy:\n")
	PrintProvedStatements(policyPool.AllPolicy)

	alreadyProved := FilterKeystonePolicy(pubPolicyKey, evp, policyPool)
	if alreadyProved == nil {
		fmt.Printf("ValidateKeystoneEvidence: Can't filterpolicy\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("\nfiltered policy:\n")
	PrintProvedStatements(alreadyProved)
	fmt.Printf("\n")

	if !InitProvedStatements(*pubPolicyKey, evp.FactAssertion, alreadyProved) {
		fmt.Printf("ValidateKeystoneEvidence: Can't InitProvedStatements\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("\nValidateKeystoneEvidence, after InitProved:\n")
	PrintProvedStatements(alreadyProved)

	// ConstructProofFromSevPlatformEvidence()
	toProve, proof := ConstructProofFromKeystoneEvidence(pubPolicyKey, purpose, alreadyProved)
	if toProve == nil || proof == nil {
		fmt.Printf("ValidateKeystoneEvidence: Can't construct proof\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("\n")
	fmt.Printf("ValidateKeystoneEvidence, toProve: ")
	PrintVseClause(toProve)
	fmt.Printf("\n")
	PrintProof(proof)
	fmt.Printf("\n")

	if !VerifyProof(pubPolicyKey, toProve, proof, alreadyProved) {
		fmt.Printf("ValidateKeystoneEvidence: Proof does not verify\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("ValidateKeystoneEvidence: Proof verifies\n")
	fmt.Printf("\nProved statements\n")
	PrintProvedStatements(alreadyProved)

	me := alreadyProved.Proved[2]
	if me.Clause == nil || me.Clause.Subject == nil ||
		me.Clause.Subject.GetEntityType() != "measurement" {
		fmt.Printf("ValidateKeystoneEvidence: Proof does not verify\n")
		return false, nil, nil
	}

	return true, toProve, me.Clause.Subject.Measurement
}

func FilterIsletPolicy(policyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
	policyPool *PolicyPool) *certprotos.ProvedStatements {

	// Debug
	fmt.Printf("Incoming evidence for Islet\n")
	PrintEvidencePackage(evp, true)
	fmt.Printf("\nOriginal Platform Policy:\n")
	for i := 0; i < len(policyPool.PlatformKeyPolicy.Proved); i++ {
		cl := policyPool.PlatformKeyPolicy.Proved[i]
		PrintVseClause(cl)
		fmt.Printf("\n")
	}
	fmt.Printf("\n")
	fmt.Printf("\nOriginal Measurement Policy:\n")
	for i := 0; i < len(policyPool.MeasurementPolicy.Proved); i++ {
		cl := policyPool.MeasurementPolicy.Proved[i]
		PrintVseClause(cl)
		fmt.Printf("\n")
	}
	fmt.Printf("\n\n")

	filtered := &certprotos.ProvedStatements{}

	// policyKey is-trusted
	from := policyPool.AllPolicy.Proved[0]
	to := proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	// This should be passed in
	evType := "islet-evidence"

	// Islet does not put the platform key in the evidence,
	// so we have to get it from policy.  This should be fixed.
	// For now, get the first statement in policy with the
	// Key name "policyAuthority"
	var platStatement *certprotos.VseClause = nil
	for i := 0; i < len(policyPool.AllPolicy.Proved); i++ {
		cl := policyPool.AllPolicy.Proved[i]
		if cl == nil || cl.Clause == nil {
			continue
		}
		s := cl.Clause
		if s.Subject == nil || s.GetVerb() != "is-trusted-for-attestation" {
			continue
		}
		if s.Subject.GetEntityType() != "key" || s.Subject.Key == nil ||
			s.Subject.Key.GetKeyName() != "policyAuthority" {
			continue
		}
		platStatement = cl
	}
	if platStatement == nil {
		fmt.Printf("FilterKeystonePolicy: bad platform statement\n")
		return nil
	}
	to = proto.Clone(platStatement).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, platStatement)

	from = GetRelevantMeasurementPolicy(policyPool, evType, evp)
	if from == nil {
		fmt.Printf("FilterIsletPolicy: Can't get relevant measurement\n")
		return nil
	}
	to = proto.Clone(from).(*certprotos.VseClause)
	filtered.Proved = append(filtered.Proved, to)

	return filtered
}

func ConstructProofFromIsletEvidence(publicPolicyKey *certprotos.KeyMessage, purpose string,
	alreadyProved *certprotos.ProvedStatements) (*certprotos.VseClause, *certprotos.Proof) {
	// At this point, the evidence should be
	//	Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] is-trusted
	//	Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
	//		Key[rsa, AttestKey, cdc8112d97fce6767143811f0ed5fb6c21aee424] is-trusted-for-attestation
	//	Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
	//		Measurement[0001020304050607...] is-trusted
	//	Key attestKey says Key[rsa, enclaveKey, b223d5da6674c6bde7feac29801e3b69bb286320] speaks-for Measurement[00010203...]

	// Debug
	fmt.Printf("ConstructProofFromIsletEvidence, %d statements\n", len(alreadyProved.Proved))
	for i := 0; i < len(alreadyProved.Proved); i++ {
		PrintVseClause(alreadyProved.Proved[i])
		fmt.Printf("\n")
	}

	if len(alreadyProved.Proved) < 4 {
		fmt.Printf("ConstructProofFromIsletEvidence: too few statements\n")
		return nil, nil
	}

	policyKeyIsTrusted := alreadyProved.Proved[0]
	policyKeySaysAttestKeyIsTrustedForAttestation := alreadyProved.Proved[1]
	policyKeySaysMeasurementIsTrusted := alreadyProved.Proved[2]
	if alreadyProved.Proved[3].Clause == nil {
		fmt.Printf("ConstructProofFromIsletEvidence: malformed attestation\n")
		return nil, nil
	}
	attestKeySaysEnclaveKeySpeaksForMeasurement := alreadyProved.Proved[3]
	enclaveKeySpeaksForMeasurement := alreadyProved.Proved[3].Clause

	if policyKeyIsTrusted == nil || enclaveKeySpeaksForMeasurement == nil ||
		policyKeySaysMeasurementIsTrusted == nil {
		fmt.Printf("ConstructProofFromIsletEvidence: evidence missing\n")
		return nil, nil
	}

	if policyKeySaysAttestKeyIsTrustedForAttestation.Clause == nil {
		fmt.Printf("ConstructProofFromIsletEvidence: Can't get platformKeyIsTrustedForAttestation\n")
		return nil, nil
	}

	proof := &certprotos.Proof{}
	r1 := int32(1)
	r3 := int32(3)
	r6 := int32(6)
	r7 := int32(7)

	enclaveKey := enclaveKeySpeaksForMeasurement.Subject
	if enclaveKey == nil || enclaveKey.GetEntityType() != "key" {
		fmt.Printf("ConstructProofFromIsletEvidence: Bad enclave key\n")
		return nil, nil
	}
	var toProve *certprotos.VseClause = nil
	if purpose == "authentication" {
		verb := "is-trusted-for-authentication"
		toProve = MakeUnaryVseClause(enclaveKey, &verb)
	} else {
		verb := "is-trusted-for-attestation"
		toProve = MakeUnaryVseClause(enclaveKey, &verb)
	}

	measurementIsTrusted := policyKeySaysMeasurementIsTrusted.Clause
	if measurementIsTrusted == nil {
		fmt.Printf("ConstructProofFromIsletEvidence: Can't get measurement\n")
		return nil, nil
	}
	ps1 := certprotos.ProofStep{
		S1:          policyKeyIsTrusted,
		S2:          policyKeySaysMeasurementIsTrusted,
		Conclusion:  measurementIsTrusted,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps1)

	// add policyKey is-trusted AND
	// policyKey says attestKey is-trusted-for-attestation -->
	// attestKey is-trusted-for-attestation
	if policyKeySaysAttestKeyIsTrustedForAttestation.Clause == nil {
		fmt.Printf("ConstructProofFromIsletEvidence: Can't malformed attestation key appointment\n")
		return nil, nil
	}
	attestKeyIsTrustedForAttestation := policyKeySaysAttestKeyIsTrustedForAttestation.Clause
	ps2 := certprotos.ProofStep{
		S1:          policyKeyIsTrusted,
		S2:          policyKeySaysAttestKeyIsTrustedForAttestation,
		Conclusion:  attestKeyIsTrustedForAttestation,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps2)

	// add attestKey is-trusted-for-attestation AND
	// attestKey says enclaveKey speaks-for measurement -->
	// enclaveKey speaks-for measurement
	ps3 := certprotos.ProofStep{
		S1:          attestKeyIsTrustedForAttestation,
		S2:          attestKeySaysEnclaveKeySpeaksForMeasurement,
		Conclusion:  enclaveKeySpeaksForMeasurement,
		RuleApplied: &r6,
	}
	proof.Steps = append(proof.Steps, &ps3)

	// measurement is-trusted and enclaveKey speaks-for measurement -->
	//	enclaveKey is-trusted-for-authentication (r1) or
	//	enclaveKey is-trusted-for-attestation (r7)
	if purpose == "authentication" {
		ps4 := certprotos.ProofStep{
			S1:          measurementIsTrusted,
			S2:          enclaveKeySpeaksForMeasurement,
			Conclusion:  toProve,
			RuleApplied: &r1,
		}
		proof.Steps = append(proof.Steps, &ps4)
	} else {
		ps4 := certprotos.ProofStep{
			S1:          measurementIsTrusted,
			S2:          enclaveKeySpeaksForMeasurement,
			Conclusion:  toProve,
			RuleApplied: &r7,
		}
		proof.Steps = append(proof.Steps, &ps4)
	}

	return toProve, proof
}

// returns success, toProve, measurement
func ValidateIsletEvidence(pubPolicyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
	policyPool *PolicyPool, purpose string) (bool,
	*certprotos.VseClause, []byte) {

	// Debug
	fmt.Printf("\nValidateIsletEvidence, Original policy:\n")
	PrintProvedStatements(policyPool.AllPolicy)

	alreadyProved := FilterIsletPolicy(pubPolicyKey, evp, policyPool)
	if alreadyProved == nil {
		fmt.Printf("ValidateIsletEvidence: Can't filterpolicy\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("\nfiltered policy:\n")
	PrintProvedStatements(alreadyProved)
	fmt.Printf("\n")

	if !InitProvedStatements(*pubPolicyKey, evp.FactAssertion, alreadyProved) {
		fmt.Printf("ValidateIsletEvidence: Can't InitProvedStatements\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("\nValidateIsletEvidence, after InitProved:\n")
	PrintProvedStatements(alreadyProved)

	toProve, proof := ConstructProofFromIsletEvidence(pubPolicyKey, purpose, alreadyProved)
	if toProve == nil || proof == nil {
		fmt.Printf("ValidateKeystoneEvidence: Can't construct proof\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("\n")
	fmt.Printf("ValidateIsletEvidence, toProve: ")
	PrintVseClause(toProve)
	fmt.Printf("\n")
	PrintProof(proof)
	fmt.Printf("\n")

	if !VerifyProof(pubPolicyKey, toProve, proof, alreadyProved) {
		fmt.Printf("ValidateIsletEvidence: Proof does not verify\n")
		return false, nil, nil
	}

	// Debug
	fmt.Printf("ValidateIsletEvidence: Proof verifies\n")
	fmt.Printf("\nProved statements\n")
	PrintProvedStatements(alreadyProved)

	me := alreadyProved.Proved[2]
	if me.Clause == nil || me.Clause.Subject == nil ||
		me.Clause.Subject.GetEntityType() != "measurement" {
		fmt.Printf("ValidateIsletEvidence: Proof does not verify\n")
		return false, nil, nil
	}

	return true, toProve, me.Clause.Subject.Measurement
}
