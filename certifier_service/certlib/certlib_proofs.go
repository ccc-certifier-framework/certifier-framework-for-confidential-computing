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
	"errors"
	"fmt"
	"math/big"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/sha256"
	"crypto/x509"
	"google.golang.org/protobuf/proto"
	certprotos "github.com/jlmucb/crypto/v2/certifier-framework-for-confidential-computing/certifier_service/certprotos"
	oeverify "github.com/jlmucb/crypto/v2/certifier-framework-for-confidential-computing/certifier_service/oeverify"
	gramineverify "github.com/jlmucb/crypto/v2/certifier-framework-for-confidential-computing/certifier_service/gramineverify"
)


func InitAxiom(pk certprotos.KeyMessage, ps *certprotos.ProvedStatements) bool {
	// add pk is-trusted to proved statenments
	ke := MakeKeyEntity(&pk)
	ist := "is-trusted"
	vc :=  MakeUnaryVseClause(ke, &ist)
	ps.Proved = append(ps.Proved, vc)
	return true
}

func FilterOePolicy(policyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
		original *certprotos.ProvedStatements) *certprotos.ProvedStatements {
	// Todo: Fix
        filtered :=  &certprotos.ProvedStatements {}
	for i := 0; i < len(original.Proved); i++ {
		from := original.Proved[i]
		to :=  proto.Clone(from).(*certprotos.VseClause)
		filtered.Proved = append(filtered.Proved, to)
	}

	return filtered
}

func FilterInternalPolicy(policyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
		original *certprotos.ProvedStatements) *certprotos.ProvedStatements {

	// Todo: Fix.  Normally the policy used for tests need not be filtered, but we should do it anyway.
        filtered :=  &certprotos.ProvedStatements {}
	for i := 0; i < len(original.Proved); i++ {
		from := original.Proved[i]
		to :=  proto.Clone(from).(*certprotos.VseClause)
		filtered.Proved = append(filtered.Proved, to)
	}

	return filtered
}

func FilterSevPolicy(policyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
		original *certprotos.ProvedStatements) *certprotos.ProvedStatements {
	n := len(evp.FactAssertion);
	ev := evp.FactAssertion[n - 1]
	if ev.GetEvidenceType() != "sev-attestation" {
		fmt.Printf("FilterPolicy: sev attestation expected\n")
		return nil
	}
	sevAtt := &certprotos.SevAttestationMessage{}
	err := proto.Unmarshal(ev.SerializedEvidence, sevAtt)
	if err != nil {
		fmt.Printf("FilterPolicy: can't unmarshal attest claim\n")
		return nil
	}
	if sevAtt.ReportedAttestation == nil {
		fmt.Printf("FilterPolicy: empty sev attestation\n")
		return nil
	}
	pl := GetPlatformFromSevAttest(sevAtt.ReportedAttestation)
	if pl == nil {
		fmt.Printf("FilterPolicy: can't get platform from attestation\n")
		return nil
	}
	m := GetMeasurementFromSevAttest(sevAtt.ReportedAttestation)
	if m == nil {
		fmt.Printf("FilterPolicy: can't get measurement from attestation\n")
		return nil
	}
	foundMeasurement := false
	foundPlatform := false
	alreadyProved := &certprotos.ProvedStatements{}
	alreadyProved.Proved = append(alreadyProved.Proved, original.Proved[0])
	for i := 1; i < len(original.Proved); i++ {
		vcm := original.Proved[i]
		if vcm.Subject == nil || vcm.Subject.EntityType == nil || vcm.Subject.GetEntityType() != "key" {
			fmt.Printf("FilterPolicy: Policy not signed by policy key\n")
			return nil
		}
		if !SameKey(vcm.Subject.Key, policyKey) {
			fmt.Printf("FilterPolicy: Policy not signed by policy key\n")
			return nil
		}
		cl := vcm.Clause
		if cl == nil || cl.Subject == nil || cl.Verb == nil {
			fmt.Printf("FilterPolicy: Policy statement %d malformed (1)\n", i)
			PrintVseClause(vcm)
			fmt.Printf("\n")
			return nil
		}
		// Is statement policyKey says measurement is-trusted
		if cl.Subject.GetEntityType() == "measurement" && cl.GetVerb() == "is-trusted" {
			if foundMeasurement {
				continue
			}
			if cl.Subject.Measurement == nil {
				continue
			}
			if bytes.Equal(cl.Subject.Measurement, m) {
				foundMeasurement = true
			} else {
				continue
			}
		}

		// Is statement policyKey says platform has-trusted-platform-property
		if cl.Subject.GetEntityType() == "platform" && cl.GetVerb() == "has-trusted-platform-property" {
			if cl.Subject.PlatformEnt == nil || cl.Subject.PlatformEnt.GetPlatformType() != pl.GetPlatformType() {
				continue
			}
			if foundPlatform {
				continue
			}
			if SatisfyingProperties(cl.Subject.PlatformEnt.Props, pl.Props) {
				foundPlatform = true
			} else {
				continue
			}
		}
		alreadyProved.Proved = append(alreadyProved.Proved, vcm)
	}
	if !foundMeasurement {
		fmt.Printf("FilterPolicy: measurement is empty\n")
		return nil
	}
	if !foundPlatform {
		fmt.Printf("FilterPolicy: platform is empty\n")
		return nil
	}
	return alreadyProved
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
		vse := &certprotos.VseClause {}
		err = proto.Unmarshal(cm.SerializedClaim, vse)
		if err != nil {
			fmt.Printf("Can't unmarshal vse claim\n")
			return false
		}
		alreadyProved.Proved = append(alreadyProved.Proved , vse)
	}
	return true
}

func InitProvedStatements(pk certprotos.KeyMessage, evidenceList []*certprotos.Evidence,
		ps *certprotos.ProvedStatements) bool {

	seenList := new (CertSeenList)
	seenList.maxSize = 30
	seenList.size = 0

	// Debug
	fmt.Printf("\nInitProvedStatements %d assertions\n", len(evidenceList))

	for i := 0; i < len(evidenceList); i++ {
		ev := evidenceList[i]
		if  ev.GetEvidenceType() == "signed-claim" {
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
			succeeded, serializedUD, m, err  := VerifyGramineAttestation(ev.SerializedEvidence)
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
			cl := ConstructGramineClaim(ud.EnclaveKey, m)
			if cl == nil {
				fmt.Printf("InitProvedStatements: ConstructGramineClaim failed\n")
				return false
			}
			ps.Proved = append(ps.Proved, cl)
		} else if ev.GetEvidenceType() == "oe-attestation-report" {
			// call oeVerify here and construct the statement:
			//      enclave-key speaks-for measurement
			// from the return values.  Then add it to proved statements
			// Ignore SGX TCB level check for now
			var serializedUD, m []byte
			var err error
			if i < 1  || evidenceList[i-1].GetEvidenceType() != "pem-cert-chain" {
				// No endorsement presented
				serializedUD, m, err  = oeverify.OEHostVerifyEvidence(evidenceList[i].SerializedEvidence,
					nil, false)
			} else {
				serializedUD, m, err  = oeverify.OEHostVerifyEvidence(evidenceList[i].SerializedEvidence,
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
				fmt.Printf("InitProvedStatements: ConstructKeystoneSpeaksForEnvironmentStatement failed\n")
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
				Roots:   certPool,
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

 */

	return true;
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
	c1 :=  MakeUnaryVseClause(s1, &isTrustedForAttest)
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
	tf := TimePointPlus(tn, 365 * 86400)
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
	e := &certprotos.Environment {
		ThePlatform: plat,
		TheMeasurement: m,
	}
	isEnvVerb := "is-environment"
	ee := MakeEnvironmentEntity(e)
	if ee == nil {
		fmt.Printf("ConstructSevIsEnvironmentStatement: can't make environment entity\n")
		return nil
	}
	vse := &certprotos.VseClause {
		Subject: ee,
		Verb: &isEnvVerb,
	}
	ke := MakeKeyEntity(vcekKey)
	if ke == nil {
		fmt.Printf("ConstructSevIsEnvironmentStatement: can't make vcek key entity\n")
		return nil
	}
	saysVerb := "says"
	vseSays := &certprotos.VseClause {
                Subject: ke,
                Verb: &saysVerb,
		Clause: vse,
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
	vseSpeaksFor := &certprotos.VseClause {
		Subject: eke,
		Verb: &speaksForVerb,
		Object: env,
	}
	ke := MakeKeyEntity(vcekKey)
	if ke == nil {
		fmt.Printf("ConstructSevIsEnvironmentStatement: can't make vcek key entity\n")
		return nil
	}
	saysVerb := "says"
	vseSays := &certprotos.VseClause {
                Subject: ke,
                Verb: &saysVerb,
		Clause: vseSpeaksFor,
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

// attestKey says enclaveKey speaksfor environment
func ConstructKeystoneSpeaksForMeasurementStatement(attestKey *certprotos.KeyMessage, enclaveKey *certprotos.KeyMessage,
		mEnt *certprotos.EntityMessage) *certprotos.VseClause {
	eke := MakeKeyEntity(enclaveKey)
	if eke == nil {
		fmt.Printf("ConstructKeystoneIsEnvironmentStatement: can't make enclave key entity\n")
		return nil
	}
	speaksForVerb := "speaks-for"
	vseSpeaksFor := &certprotos.VseClause {
		Subject: eke,
		Verb: &speaksForVerb,
		Object: mEnt,
	}
	ke := MakeKeyEntity(attestKey)
	if ke == nil {
		fmt.Printf("ConstructKeystoneIsEnvironmentStatement: can't make attest key entity\n")
		return nil
	}
	saysVerb := "says"
	vseSays := &certprotos.VseClause {
                Subject: ke,
                Verb: &saysVerb,
		Clause: vseSpeaksFor,
        }
	return vseSays
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
	if pol_byte & 0x08  == 1 {
		vp0 = "yes"
	}
	p0 := MakeProperty(pn0, svt, &vp0, &ce, nil)
	props.Props = append(props.Props, p0)

	pn1 := "debug"
	vp1 := "no"
	if pol_byte & 0x04  == 1 {
		vp1 = "yes"
	}
	p1 := MakeProperty(pn1, svt, &vp1, &ce, nil)
	props.Props = append(props.Props, p1)

	pn2 := "smt"
	vp2 := "no"
	if pol_byte & 0x01  == 1 {
		vp2 = "yes"
	}
	p2 := MakeProperty(pn2, svt, &vp2, &ce, nil)
	props.Props = append(props.Props, p2)

	pn3 := "migrate"
	vp3 := "no"
	if pol_byte & 0x02  == 1 {
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


	tcb := uint64(binSevAttest[0x180])
	tcb = (uint64(binSevAttest[0x181]) << 8) | tcb
	tcb = (uint64(binSevAttest[0x182]) << 16) | tcb
	tcb = (uint64(binSevAttest[0x183]) << 24) | tcb
	tcb = (uint64(binSevAttest[0x184]) << 32) | tcb
	tcb = (uint64(binSevAttest[0x185]) << 40) | tcb
	tcb = (uint64(binSevAttest[0x186]) << 48) | tcb
	tcb = (uint64(binSevAttest[0x187]) << 56) | tcb

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
		return true;
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
	if err!= nil || PK == nil {
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
	rb := sig[0:48];
	sb := sig[72:120]
	measurement := ptr[0x90: 0xc0]

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
	fmt.Printf("  Reversed R: ");
	PrintBytes(reversedR)
	fmt.Printf("\n")
	fmt.Printf("  Reversed S: ");
	PrintBytes(reversedS)
	fmt.Printf("\n")

	r :=  new(big.Int).SetBytes(reversedR)
	s :=  new(big.Int).SetBytes(reversedS)
	if !ecdsa.Verify(PK, hashOfHeader[0:48], r, s) {
		fmt.Printf("VerifySevAttestation: ecdsa.Verify failed\n")
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
	if err!= nil || PK == nil {
		fmt.Printf("VerifyKeystoneAttestation: Can't extract key.\n")
		return nil
	}

	if am.WhatWasSaid == nil {
		fmt.Printf("VerifyKeystoneAttestation: WhatWasSaid is nil.\n")
		return nil
	}
	hashedWhatWasSaid := sha256.Sum256(am.WhatWasSaid)

	// Compute hash of hash, datalen, data in enclave report
	// This is what was signed
	signedHash := sha256.Sum256(ptr[0:104])

	// Debug
	fmt.Printf("\nVerifyKeystoneAttestation\n")

	fmt.Printf("\nUser data hash in report: ")
	PrintBytes(hashedWhatWasSaid[0:32])
	fmt.Printf("\n")

	fmt.Printf("\nHash to sign: ")
	PrintBytes(signedHash[0:32])
	fmt.Printf("\n")

	measurement := ptr[0: 32]
	sig := ptr[104:248]
	byteSize := ptr[248:252]
	sigSize := int(byteSize[0]) + 256 * int(byteSize[1]) + 256 * 256 * int(byteSize[2]) +256 * 256 * 256 * int(byteSize[3])

	// Debug
	fmt.Printf("\nHash of WhatWasSaid: ")
	PrintBytes(hashedWhatWasSaid[0:32])
	fmt.Printf("\n")
	fmt.Printf("Measurement: ")
	PrintBytes(measurement)
	fmt.Printf("\n")
	fmt.Printf("Signature: ")
	PrintBytes(sig)
	fmt.Printf("\n")
	fmt.Printf("\nsig size (%d): ", sigSize)
	PrintBytes(byteSize)
	fmt.Printf("\n")

	// check signature
	rb := sig[0:32];
	sb := sig[32:sigSize]
	reversedR := LittleToBigEndian(rb)
	reversedS := LittleToBigEndian(sb)
	if reversedR == nil || reversedS == nil {
		fmt.Printf("VerifyKeystoneAttestation: reversed bytes failed\n")
		return nil
	}

/*
	// Debug
	fmt.Printf("  Reversed R: ");
	PrintBytes(reversedR)
	fmt.Printf("\n")
	fmt.Printf("  Reversed S: ");
	PrintBytes(reversedS)
	fmt.Printf("\n")

	r :=  new(big.Int).SetBytes(reversedR)
	s :=  new(big.Int).SetBytes(reversedS)
	if !ecdsa.Verify(PK, signedHash[0:32], r, s) {
*/
	if !ecdsa.VerifyASN1(PK, signedHash[0:32], sig[0:sigSize]) {
		fmt.Printf("VerifyKeystoneAttestation: ecdsa.Verify failed\n")
                // Todo: Fix
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
		if (!SameEntity(c1.Subject, c2.Object)) {
			return false
		}

		if c.Subject == nil || c.Verb == nil || c.Object != nil  || c.Clause != nil {
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
	if (!SameEntity(c1.Subject, c2.Object)) {
		return false
	}

	if c.Subject == nil || c.Verb == nil || c.Object != nil  || c.Clause != nil {
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
	if !SatisfyingProperties( c2.Subject.PlatformEnt.Props, c1.Subject.EnvironmentEnt.ThePlatform.Props,) {
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
	if (!bytes.Equal(c2.Subject.Measurement, c1.Subject.EnvironmentEnt.TheMeasurement)) {
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
	switch(rule) {
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

	tree := PredicateDominance {
		Predicate: "is-trusted",
		FirstChild: nil,
		Next: nil,
	}

	if !InitDominance(&tree) {
		fmt.Printf("Can't init Dominance tree\n");
		return false;
	}

	for i := 0; i < len(p.Steps); i++ {
		s1 := p.Steps[i].S1
		s2 := p.Steps[i].S2
		c := p.Steps[i].Conclusion
		if s1 == nil || s2 == nil || c == nil {
			fmt.Printf("Bad proof step\n")
			return false;
		}
		if !StatementAlreadyProved(s1, ps)  {
			continue
		}
		if !StatementAlreadyProved(s2, ps)  {
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

func ConstructProofFromOeEvidenceWithoutEndorsement(publicPolicyKey *certprotos.KeyMessage, purpose string, alreadyProved *certprotos.ProvedStatements)  (*certprotos.VseClause, *certprotos.Proof) {
	if len(alreadyProved.Proved) < 3 {
		fmt.Printf("ConstructProofFromOeEvidence: too few statements\n")
		return nil, nil
	}

	policyKeyIsTrusted :=  alreadyProved.Proved[0]
	policyKeySaysMeasurementIsTrusted := alreadyProved.Proved[1]
	enclaveKeySpeaksForMeasurement :=  alreadyProved.Proved[2]

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
	ps1 := certprotos.ProofStep {
		S1: policyKeyIsTrusted,
		S2: policyKeySaysMeasurementIsTrusted,
		Conclusion: measurementIsTrusted,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps1)

	// measurement is-trusted and enclaveKey speaks-for measurement -->
	//	enclaveKey is-trusted-for-authentication (r1) or
	//	enclaveKey is-trusted-for-attestation (r7)
	if purpose == "authentication" {
		ps2 := certprotos.ProofStep {
			S1: measurementIsTrusted,
			S2: enclaveKeySpeaksForMeasurement,
			Conclusion: toProve,
			RuleApplied: &r1,
		}
		proof.Steps = append(proof.Steps, &ps2)
	} else {
		ps2 := certprotos.ProofStep {
			S1: measurementIsTrusted,
			S2: enclaveKeySpeaksForMeasurement,
			Conclusion: toProve,
			RuleApplied: &r7,
		}
		proof.Steps = append(proof.Steps, &ps2)
	}

        return toProve, proof

}

func ConstructProofFromOeEvidenceWithEndorsement(publicPolicyKey *certprotos.KeyMessage, purpose string, alreadyProved *certprotos.ProvedStatements)  (*certprotos.VseClause, *certprotos.Proof) {
	if len(alreadyProved.Proved) < 4 {
		fmt.Printf("ConstructProofFromOeEvidence: too few statements\n")
		return nil, nil
	}

	policyKeyIsTrusted :=  alreadyProved.Proved[0]
	policyKeySaysPlatformKeyIsTrustedForAttestation := alreadyProved.Proved[1]
	policyKeySaysMeasurementIsTrusted := alreadyProved.Proved[2]
	platformSaysEnclaveKeySpeaksForMeasurement :=  alreadyProved.Proved[3]

	if platformSaysEnclaveKeySpeaksForMeasurement.Clause == nil {
		fmt.Printf("ConstructProofFromOeEvidence: can't get enclaveKeySpeaksForMeasurement\n")
		return nil, nil
	}
	enclaveKeySpeaksForMeasurement :=  platformSaysEnclaveKeySpeaksForMeasurement.Clause
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
	ps1 := certprotos.ProofStep {
		S1: policyKeyIsTrusted,
		S2: policyKeySaysMeasurementIsTrusted,
		Conclusion: measurementIsTrusted,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps1)

	ps2 := certprotos.ProofStep {
		S1: policyKeyIsTrusted,
		S2: policyKeySaysPlatformKeyIsTrustedForAttestation,
		Conclusion: platformKeyIsTrustedForAttestation,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps2)

	ps3 := certprotos.ProofStep {
		S1: platformKeyIsTrustedForAttestation,
		S2: platformSaysEnclaveKeySpeaksForMeasurement,
		Conclusion: enclaveKeySpeaksForMeasurement,
		RuleApplied: &r6,
	}
	proof.Steps = append(proof.Steps, &ps3)

	// measurement is-trusted and enclaveKey speaks-for measurement -->
	//	enclaveKey is-trusted-for-authentication (r1) or
	//	enclaveKey is-trusted-for-attestation (r7)
	if purpose == "authentication" {
		ps4 := certprotos.ProofStep {
			S1: measurementIsTrusted,
			S2: enclaveKeySpeaksForMeasurement,
			Conclusion: toProve,
			RuleApplied: &r1,
		}
		proof.Steps = append(proof.Steps, &ps4)
	} else {
		ps4 := certprotos.ProofStep {
			S1: measurementIsTrusted,
			S2: enclaveKeySpeaksForMeasurement,
			Conclusion: toProve,
			RuleApplied: &r7,
		}
		proof.Steps = append(proof.Steps, &ps4)
	}

        return toProve, proof
}

func ConstructProofFromOeEvidence(publicPolicyKey *certprotos.KeyMessage, purpose string, alreadyProved *certprotos.ProvedStatements)  (*certprotos.VseClause, *certprotos.Proof) {
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
	for i := 0; i < len(alreadyProved.Proved);  i++ {
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
func ConstructProofFromInternalPlatformEvidence(publicPolicyKey *certprotos.KeyMessage, purpose string, alreadyProved *certprotos.ProvedStatements)  (*certprotos.VseClause, *certprotos.Proof) {
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
		return nil, nil
	}

        proof := &certprotos.Proof{}
        r1 := int32(1)
        r3 := int32(3)
        r5 := int32(5)
        r6 := int32(6)
        r7 := int32(7)

        policyKeyIsTrusted := alreadyProved.Proved[0]

        policyKeySaysPlatformKeyIsTrusted := alreadyProved.Proved[1]
        platformKeyIsTrusted := policyKeySaysPlatformKeyIsTrusted.Clause
        ps1 := certprotos.ProofStep {
                S1: policyKeyIsTrusted,
                S2: policyKeySaysPlatformKeyIsTrusted,
                Conclusion: platformKeyIsTrusted,
                RuleApplied: &r5,
        }
        proof.Steps = append(proof.Steps, &ps1)

        policyKeySaysMeasurementIsTrusted := alreadyProved.Proved[2]
        measurementIsTrusted := policyKeySaysMeasurementIsTrusted.Clause
        ps2 := certprotos.ProofStep {
                S1: policyKeyIsTrusted,
                S2: policyKeySaysMeasurementIsTrusted,
                Conclusion: measurementIsTrusted,
                RuleApplied: &r3,
        }
        proof.Steps = append(proof.Steps, &ps2)

        platformKeySaysAttestKeyIsTrusted := alreadyProved.Proved[3]
        attestKeyIsTrusted := platformKeySaysAttestKeyIsTrusted.Clause
        ps3 := certprotos.ProofStep {
                S1: platformKeyIsTrusted,
                S2: platformKeySaysAttestKeyIsTrusted,
                Conclusion: attestKeyIsTrusted,
                RuleApplied: &r5,
        }
        proof.Steps = append(proof.Steps, &ps3)

        attestKeySaysEnclaveKeySpeaksForMeasurement := alreadyProved.Proved[4]
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
                toProve =  MakeUnaryVseClause(enclaveKeySpeaksForMeasurement.Subject,
                        &isTrustedForAttest)
                ps5 := certprotos.ProofStep {
                S1: measurementIsTrusted,
                S2: enclaveKeySpeaksForMeasurement,
                Conclusion: toProve,
                RuleApplied: &r7,
                }
                proof.Steps = append(proof.Steps, &ps5)
        } else {
                toProve =  MakeUnaryVseClause(enclaveKeySpeaksForMeasurement.Subject,
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

func ConstructProofFromSevPlatformEvidence(publicPolicyKey *certprotos.KeyMessage, purpose string, alreadyProved *certprotos.ProvedStatements)  (*certprotos.VseClause, *certprotos.Proof) {

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
	policyKeyIsTrusted :=  alreadyProved.Proved[0]
	policyKeySaysMeasurementIsTrusted :=  alreadyProved.Proved[2]
	if policyKeySaysMeasurementIsTrusted.Clause == nil {
		fmt.Printf("ConstructProofFromPlatformEvidence: Policy key says measurement is-trusted is malformed\n")
		return nil, nil
	}
	measurementIsTrusted :=  policyKeySaysMeasurementIsTrusted.Clause
	ps1 := certprotos.ProofStep {
		S1: policyKeyIsTrusted,
		S2: policyKeySaysMeasurementIsTrusted,
		Conclusion: measurementIsTrusted,
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
	ps2 := certprotos.ProofStep {
		S1: policyKeyIsTrusted,
		S2: policyKeySaysArkKeyIsTrusted,
		Conclusion: arkKeyIsTrusted,
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
	ps3 := certprotos.ProofStep {
		S1: arkKeyIsTrusted,
		S2: arkKeySaysAskKeyIsTrusted,
		Conclusion: askKeyIsTrusted,
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
	ps4 := certprotos.ProofStep {
		S1: askKeyIsTrusted,
		S2: askKeySaysVcekKeyIsTrusted,
		Conclusion: vcekKeyIsTrusted,
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
	ps5 := certprotos.ProofStep {
		S1: vcekKeyIsTrusted,
		S2: vcekSaysIsEnvironment,
		Conclusion: isEnvironment,
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
	ps6 := certprotos.ProofStep {
		S1: policyKeyIsTrusted,
		S2: policyKeySaysPlatformHasTrustedPlatformProperty,
		Conclusion: platformHasTrustedPlatformProperty,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps6)

	//    "environment(platform, measurement) is-environment" AND
	//        "platform[amd-sev-snp, no-debug,...] has-trusted-platform-property" -->
	//        "environment(platform, measurement) environment-platform-is-trusted" [3, ]
	pitVerb := "environment-platform-is-trusted"
	environmentPlatformIsTrusted := &certprotos.VseClause {
		Subject: isEnvironment.Subject,
		Verb: &pitVerb,
	}
	ps8 := certprotos.ProofStep {
		S1: isEnvironment,
		S2: platformHasTrustedPlatformProperty,
		Conclusion: environmentPlatformIsTrusted,
		RuleApplied: &r8,
	}
	proof.Steps = append(proof.Steps, &ps8)

	//    "environment(platform, measurement) is-environment" AND
	//        "measurement is-trusted" -->
	//        "environment(platform, measurement) environment-measurement-is-trusted"
	emitVerb := "environment-measurement-is-trusted"
	environmentMeasurementIsTrusted := &certprotos.VseClause {
		Subject: isEnvironment.Subject,
		Verb: &emitVerb,
	}
	ps9 := certprotos.ProofStep {
		S1: isEnvironment,
		S2: measurementIsTrusted,
		Conclusion: environmentMeasurementIsTrusted,
		RuleApplied: &r9,
	}
	proof.Steps = append(proof.Steps, &ps9)


	//    "environment(platform, measurement) environment-platform-is-trusted" AND
	//        "environment(platform, measurement) environment-measurement-is-trusted"  -->
	//        "environment(platform, measurement) is-trusted
	eitVerb := "is-trusted"
	environmentIsTrusted := &certprotos.VseClause {
		Subject: isEnvironment.Subject,
		Verb: &eitVerb,
	}
	ps10 := certprotos.ProofStep {
		S1: environmentMeasurementIsTrusted,
		S2: environmentPlatformIsTrusted,
		Conclusion: environmentIsTrusted,
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
	ps11 := certprotos.ProofStep {
		S1: vcekKeyIsTrusted,
		S2: vcekSaysEnclaveKeySpeaksForEnvironment,
		Conclusion: enclaveKeySpeaksForEnvironment,
		RuleApplied: &r6,
	}
	proof.Steps = append(proof.Steps, &ps11)

	if purpose == "attestation" {
		itfaVerb := "is-trusted-for-attestation"
		enclaveKeyIsTrusted := &certprotos.VseClause {
			Subject: enclaveKeySpeaksForEnvironment.Subject,
			Verb: &itfaVerb,
		}
		ps12 := certprotos.ProofStep {
			S1: environmentIsTrusted,
			S2: enclaveKeySpeaksForEnvironment,
			Conclusion: enclaveKeyIsTrusted,
			RuleApplied: &r6,
		}
		proof.Steps = append(proof.Steps, &ps12)

		toProve := enclaveKeyIsTrusted
		return toProve, proof
	} else {
		itfaVerb := "is-trusted-for-authentication"
		enclaveKeyIsTrusted := &certprotos.VseClause {
			Subject: enclaveKeySpeaksForEnvironment.Subject,
			Verb: &itfaVerb,
		}
		ps12 := certprotos.ProofStep {
			S1: environmentIsTrusted,
			S2: enclaveKeySpeaksForEnvironment,
			Conclusion: enclaveKeyIsTrusted,
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
		originalPolicy *certprotos.ProvedStatements, purpose string) (bool,
                *certprotos.VseClause, []byte) {

	// Debug
	fmt.Printf("\nValidateInternalEvidence: original policy:\n")
	PrintProvedStatements(originalPolicy)

	alreadyProved := FilterInternalPolicy(pubPolicyKey, evp, originalPolicy)
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
		originalPolicy *certprotos.ProvedStatements, purpose string) (bool,
                *certprotos.VseClause, []byte) {

	// Debug
	fmt.Printf("\nValidateOeEvidence, Original policy:\n")
	PrintProvedStatements(originalPolicy)

	alreadyProved := FilterOePolicy(pubPolicyKey, evp, originalPolicy)
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

        // ConstructProofFromSevPlatformEvidence()
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
        PrintProvedStatements(alreadyProved);

	var me *certprotos.VseClause
	for i := 1; i <= len(alreadyProved.Proved);  i++ {
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
		originalPolicy *certprotos.ProvedStatements, purpose string) (bool,
                *certprotos.VseClause, []byte) {

	// Debug
	fmt.Printf("\nValidateSevEvidence, Original policy:\n")
	PrintProvedStatements(originalPolicy)

	alreadyProved := FilterSevPolicy(pubPolicyKey, evp, originalPolicy)
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
        PrintProvedStatements(alreadyProved);

	me := alreadyProved.Proved[2]
	if me.Clause == nil || me.Clause.Subject == nil ||
			me.Clause.Subject.GetEntityType() != "measurement" {
                fmt.Printf("ValidateSevEvidence: Proof does not verify\n")
		return false, nil, nil
	}

	return true, toProve, me.Clause.Subject.Measurement
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


func FilterGraminePolicy(policyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
		original *certprotos.ProvedStatements) *certprotos.ProvedStatements {

	// Todo: Fix
        filtered :=  &certprotos.ProvedStatements {}
	for i := 0; i < len(original.Proved); i++ {
		from := original.Proved[i]
		to :=  proto.Clone(from).(*certprotos.VseClause)
		filtered.Proved = append(filtered.Proved, to)
	}

	return filtered
}


func ConstructProofFromGramineEvidence(publicPolicyKey *certprotos.KeyMessage, purpose string,
		alreadyProved *certprotos.ProvedStatements)  (*certprotos.VseClause, *certprotos.Proof) {
        // At this point, the evidence should be
	//	Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] is-trusted
	//	Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
	//		Key[rsa, ARKKey, cdc8112d97fce6767143811f0ed5fb6c21aee424] is-trusted-for-attestation
	//	Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
	//		Measurement[0001020304050607...] is-trusted
	//	Key[rsa, ARKKey, cdc8112d97fce6767143811f0ed5fb6c21aee424] says
	//		Key[rsa, ARKKey, cdc8112d97fce6767143811f0ed5fb6c21aee424] is-trusted-for-attestation
	//	Key[rsa, attestKey, b223d5da6674c6bde7feac29801e3b69bb286320] speaks-for Measurement[00010203...]

	// Debug
	fmt.Printf("ConstructProofFromGramineEvidence, %d statements\n", len(alreadyProved.Proved))
	for i := 0; i < len(alreadyProved.Proved);  i++ {
		PrintVseClause(alreadyProved.Proved[i])
		fmt.Printf("\n")
	}

	if len(alreadyProved.Proved) < 5 {
		fmt.Printf("ConstructProofFromGramineEvidence: too few statements\n")
		return nil, nil
	}

	policyKeyIsTrusted :=  alreadyProved.Proved[0]
	policyKeySaysPlatformKeyIsTrustedForAttestation := alreadyProved.Proved[1]
	policyKeySaysMeasurementIsTrusted := alreadyProved.Proved[2]
	enclaveKeySpeaksForMeasurement :=  alreadyProved.Proved[4]

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
	ps1 := certprotos.ProofStep {
		S1: policyKeyIsTrusted,
		S2: policyKeySaysMeasurementIsTrusted,
		Conclusion: measurementIsTrusted,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps1)

	// measurement is-trusted and enclaveKey speaks-for measurement -->
	//	enclaveKey is-trusted-for-authentication (r1) or
	//	enclaveKey is-trusted-for-attestation (r7)
	if purpose == "authentication" {
		ps4 := certprotos.ProofStep {
			S1: measurementIsTrusted,
			S2: enclaveKeySpeaksForMeasurement,
			Conclusion: toProve,
			RuleApplied: &r1,
		}
		proof.Steps = append(proof.Steps, &ps4)
	} else {
		ps4 := certprotos.ProofStep {
			S1: measurementIsTrusted,
			S2: enclaveKeySpeaksForMeasurement,
			Conclusion: toProve,
			RuleApplied: &r7,
		}
		proof.Steps = append(proof.Steps, &ps4)
	}

        return toProve, proof
}

// returns success, toProve, measurement
func ValidateGramineEvidence(pubPolicyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
		originalPolicy *certprotos.ProvedStatements, purpose string) (bool,
                *certprotos.VseClause, []byte) {

	// Debug
	fmt.Printf("\nValidateGramineEvidence, Original policy:\n")
	PrintProvedStatements(originalPolicy)

	alreadyProved := FilterGraminePolicy(pubPolicyKey, evp, originalPolicy)
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
        PrintProvedStatements(alreadyProved);

	me := alreadyProved.Proved[2]
	if me.Clause == nil || me.Clause.Subject == nil ||
			me.Clause.Subject.GetEntityType() != "measurement" {
                fmt.Printf("ValidateGramineEvidence: Proof does not verify\n")
		return false, nil, nil
	}

	return true, toProve, me.Clause.Subject.Measurement
}


func FilterKeystonePolicy(policyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
		original *certprotos.ProvedStatements) *certprotos.ProvedStatements {

	// Todo: Fix when we import new filter framework
        filtered :=  &certprotos.ProvedStatements {}
	for i := 0; i < len(original.Proved); i++ {
		from := original.Proved[i]
		to :=  proto.Clone(from).(*certprotos.VseClause)
		filtered.Proved = append(filtered.Proved, to)
	}

	return filtered
}


func ConstructProofFromKeystoneEvidence(publicPolicyKey *certprotos.KeyMessage, purpose string,
		alreadyProved *certprotos.ProvedStatements)  (*certprotos.VseClause, *certprotos.Proof) {
        // At this point, the evidence should be
	//	Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] is-trusted
	//	Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
	//		Key[rsa, AttestKey, cdc8112d97fce6767143811f0ed5fb6c21aee424] is-trusted-for-attestation
	//	Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
	//		Measurement[0001020304050607...] is-trusted
	//	Key attestKey says Key[rsa, enclaveKey, b223d5da6674c6bde7feac29801e3b69bb286320] speaks-for Measurement[00010203...]

	// Debug
	fmt.Printf("ConstructProofFromKeystoneEvidence, %d statements\n", len(alreadyProved.Proved))
	for i := 0; i < len(alreadyProved.Proved);  i++ {
		PrintVseClause(alreadyProved.Proved[i])
		fmt.Printf("\n")
	}

	if len(alreadyProved.Proved) < 4 {
		fmt.Printf("ConstructProofFromKeystoneEvidence: too few statements\n")
		return nil, nil
	}

	policyKeyIsTrusted :=  alreadyProved.Proved[0]
	policyKeySaysAttestKeyIsTrustedForAttestation := alreadyProved.Proved[1]
	policyKeySaysMeasurementIsTrusted := alreadyProved.Proved[2]
	if alreadyProved.Proved[3].Clause == nil {
		fmt.Printf("ConstructProofFromKeystoneEvidence: malformed attestation\n")
		return nil, nil
	}
	attestKeySaysEnclaveKeySpeaksForMeasurement := alreadyProved.Proved[3]
	enclaveKeySpeaksForMeasurement :=  alreadyProved.Proved[3].Clause

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
	ps1 := certprotos.ProofStep {
		S1: policyKeyIsTrusted,
		S2: policyKeySaysMeasurementIsTrusted,
		Conclusion: measurementIsTrusted,
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
	ps2 := certprotos.ProofStep {
		S1: policyKeyIsTrusted,
		S2: policyKeySaysAttestKeyIsTrustedForAttestation,
		Conclusion: attestKeyIsTrustedForAttestation,
		RuleApplied: &r3,
	}
	proof.Steps = append(proof.Steps, &ps2)

	// add attestKey is-trusted-for-attestation AND
	// attestKey says enclaveKey speaks-for measurement -->
	// enclaveKey speaks-for measurement
	ps3 := certprotos.ProofStep {
		S1: attestKeyIsTrustedForAttestation,
		S2: attestKeySaysEnclaveKeySpeaksForMeasurement,
		Conclusion: enclaveKeySpeaksForMeasurement,
		RuleApplied: &r6,
	}
	proof.Steps = append(proof.Steps, &ps3)

	// measurement is-trusted and enclaveKey speaks-for measurement -->
	//	enclaveKey is-trusted-for-authentication (r1) or
	//	enclaveKey is-trusted-for-attestation (r7)
	if purpose == "authentication" {
		ps4 := certprotos.ProofStep {
			S1: measurementIsTrusted,
			S2: enclaveKeySpeaksForMeasurement,
			Conclusion: toProve,
			RuleApplied: &r1,
		}
		proof.Steps = append(proof.Steps, &ps4)
	} else {
		ps4 := certprotos.ProofStep {
			S1: measurementIsTrusted,
			S2: enclaveKeySpeaksForMeasurement,
			Conclusion: toProve,
			RuleApplied: &r7,
		}
		proof.Steps = append(proof.Steps, &ps4)
	}

        return toProve, proof
}

// returns success, toProve, measurement
func ValidateKeystoneEvidence(pubPolicyKey *certprotos.KeyMessage, evp *certprotos.EvidencePackage,
		originalPolicy *certprotos.ProvedStatements, purpose string) (bool,
                *certprotos.VseClause, []byte) {

	// Debug
	fmt.Printf("\nValidateKeystoneEvidence, Original policy:\n")
	PrintProvedStatements(originalPolicy)

	alreadyProved := FilterKeystonePolicy(pubPolicyKey, evp, originalPolicy)
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
        PrintProvedStatements(alreadyProved);

	me := alreadyProved.Proved[2]
	if me.Clause == nil || me.Clause.Subject == nil ||
			me.Clause.Subject.GetEntityType() != "measurement" {
                fmt.Printf("ValidateKeystoneEvidence: Proof does not verify\n")
		return false, nil, nil
	}

	return true, toProve, me.Clause.Subject.Measurement
}
