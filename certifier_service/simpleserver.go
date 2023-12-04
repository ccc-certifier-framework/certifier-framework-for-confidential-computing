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
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/golang/protobuf/proto"
	certlib "github.com/vmware-research/certifier-framework-for-confidential-computing/certifier_service/certlib"
	certprotos "github.com/vmware-research/certifier-framework-for-confidential-computing/certifier_service/certprotos"
	// NOTE: Enable this line when you enable the test-code in main().
	// gramineverify "github.com/vmware-research/certifier-framework-for-confidential-computing/certifier_service/gramineverify"
)

var operation = flag.String("operation", "certifier-service",
	"operation name: certifier-service, key-service, convert-key or provision-keys")

var enclaveType = flag.String("enclave_type", "simulated-enclave", "enclave type")

var getPolicyKeyFromSecureStore = flag.Bool("get_key_from_secure_store", false, "get policy private key from store")

var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")

var keyServerHost = flag.String("key_service_host", "localhost", "address for client/server")
var keyServerPort = flag.String("key_service_port", "8127", "port for client/server")

var policyStoreFile = flag.String("policy_store", "store", "policy store")

var policyKeyFile = flag.String("policy_key_file", "policy_key_file.bin", "key file name")
var policyCertFile = flag.String("policy_cert_file", "policy_cert_file.bin", "cert file name")
var readPolicy = flag.Bool("readPolicy", true, "read policy")
var policyFile = flag.String("policyFile", "./certlib/policy.bin", "policy file name")

var attestKeyFile = flag.String("attest_key_file", "attest_key_file.bin", "attest key file name")
var measurementFile = flag.String("measurement_file", "certifier_measurement_file.bin", "measurement key file name")
var attestEndorsementFile = flag.String("endorsement_file", "platform_attest_endorsement.bin", "endorsement file name")

var arkFile = flag.String("ark_file", "ark_cert.der", "ARK cert file name")
var askFile = flag.String("ask_file", "ask_cert.der", "ASK cert file name")
var vcekFile = flag.String("vcek_file", "vcek_cert.der", "VCEK cert file name")

var loggingSequenceNumber = *flag.Int("loggingSequenceNumber", 1, "sequence number for logging")
var enableLog = flag.Bool("enableLog", false, "enable logging")
var logDir = flag.String("logDir", ".", "log directory")
var logFile = flag.String("logFile", "simpleserver.log", "log file name")

var privatePolicyKey *certprotos.KeyMessage = nil
var publicPolicyKey *certprotos.KeyMessage = nil
var serializedPolicyCert []byte
var policyCert *x509.Certificate = nil

var sn uint64 = uint64(time.Now().UnixNano())
var duration float64 = 365.0 * 86400

var logging bool = false
var logger *log.Logger
var dataPacketFileNum int = loggingSequenceNumber

var extendedGramine bool = false

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

var signedPolicy *certprotos.SignedClaimSequence = &certprotos.SignedClaimSequence{}
var policyPool certlib.PolicyPool

// At init, we retrieve the policy key and the rules to evaluate
func initCertifierService(useStore bool) bool {

	if *enableLog {
		logging = initLog()
	}

	if useStore {
		// Debug
		fmt.Printf("Initializing CertifierService from store: %s, cert file: %s\n",
			*policyKeyFile, *policyStoreFile)

		if *enclaveType == "simulated-enclave" {
			blank := ""
			err := certlib.TEESimulatedInit(blank, *attestKeyFile, *measurementFile, *attestEndorsementFile)
			if err != nil {
				fmt.Printf("main: failed to initialize simulated enclave\n")
				os.Exit(1)
			}
		}

		ps := certlib.NewPolicyStore(100)
		if ps == nil {
			fmt.Printf("initCertifier: can't init policy store\n")
			return false
		}
		if !certlib.RecoverPolicyStore(*enclaveType, *policyStoreFile, ps) {
			fmt.Printf("initCertifier: can't recover policy store\n")
			return false
		}
		ent := certlib.FindPolicyStoreEntry(ps, "policy-key", "key")
		if ent < 0 {
			fmt.Printf("initCertifier: can't find policy key in store\n")
			return false
		}
		privatePolicyKey = &certprotos.KeyMessage{}
		err := proto.Unmarshal(ps.Entries[ent].Value, privatePolicyKey)
		if err != nil {
			fmt.Printf("initCertifier: Can't unmarshal policy keyfrom store\n")
			return false
		}
		fmt.Printf("Recovered policy key from store\n")
	} else {

		// Debug
		fmt.Printf("Initializing CertifierService from file: %s, cert file: %s\n",
			*policyKeyFile, *policyCertFile)
		serializedKey, err := os.ReadFile(*policyKeyFile)
		if err != nil {
			fmt.Println("initCertifier: can't read key file, ", err)
			return false
		}
		privatePolicyKey = &certprotos.KeyMessage{}
		err = proto.Unmarshal(serializedKey, privatePolicyKey)
		if err != nil {
			fmt.Printf("initCertifier: Can't unmarshal serialized policy key\n")
			return false
		}
		fmt.Printf("Read policy key file\n")
	}

	serializedPolicyCert, err := os.ReadFile(*policyCertFile)
	if err != nil {
		fmt.Println("initCertifier: can't read policy cert file, ", err)
		return false
	}
	policyCert, err = x509.ParseCertificate(serializedPolicyCert)
	if err != nil {
		fmt.Println("initCertifier: Can't Parse policy cert, ", err)
		return false
	}
	fmt.Printf("Parsed certificate\n")

	publicPolicyKey = certlib.InternalPublicFromPrivateKey(privatePolicyKey)
	if publicPolicyKey == nil {
		fmt.Printf("initCertifier: Can't get public policy key\n")
		return false
	}

	if policyFile == nil {
		fmt.Printf("initCertifier: No policy file\n")
		return false
	}

	// Read policy

	// Debug
	fmt.Printf("Getting Policy file: %s\n", *policyFile)

	serializedPolicy, err := os.ReadFile(*policyFile)
	if err != nil {
		fmt.Printf("initCertifier: Can't read policy\n")
		return false
	}
	fmt.Printf("Read Policy\n")

	err = proto.Unmarshal(serializedPolicy, signedPolicy)
	if err != nil {
		fmt.Printf("initCertifier: Can't unmarshal signed policy\n")
		return false
	}
	fmt.Printf("Deserialized Policy\n")

	var originalPolicy *certprotos.ProvedStatements = &certprotos.ProvedStatements{}
	if !certlib.InitAxiom(*publicPolicyKey, originalPolicy) {
		fmt.Printf("initCertifier: Can't InitAxiom\n")
		return false
	}
	fmt.Printf("InitAxiom succeeded\n")

	if !certlib.InitPolicy(publicPolicyKey, signedPolicy, originalPolicy) {
		fmt.Printf("initCertifier: Couldn't initialize policy\n")
		return false
	}
	fmt.Printf("InitPolicy succeeded\n")

	if !certlib.InitPolicyPool(&policyPool, originalPolicy) {
		fmt.Printf("initCertifier: Can't init policy pool\n")
		return false
	}
	fmt.Printf("InitPolicyPool succeeded\n")

	if !certlib.InitSimulatedEnclave() {
		fmt.Printf("initCertifier: Can't init simulated enclave\n")
		return false
	}
	fmt.Printf("InitSimulatedEnclave succeeded, all initialized\n")

	return true
}

//	--------------------------------------------------------------------------------------

func logRequest(b []byte) *string {
	if b == nil {
		return nil
	}
	s := strconv.Itoa(dataPacketFileNum)
	dataPacketFileNum = dataPacketFileNum + 1
	fileName := *logDir + "/" + "SSReq" + "-" + s
	if ioutil.WriteFile(fileName, b, 0666) != nil {
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
	if ioutil.WriteFile(fileName, b, 0666) != nil {
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

func ValidateRequestAndObtainToken(remoteIP string, pubKey *certprotos.KeyMessage, privKey *certprotos.KeyMessage,
	policyPool *certlib.PolicyPool, evType string, purpose string, ep *certprotos.EvidencePackage) (bool, []byte) {

	// evidenceType should be "vse-attestation-package", "gramine-evidence",
	//      "oe-evidence" or "sev-platform-package"
	var toProve *certprotos.VseClause = nil
	var measurement []byte = nil
	var success bool

	if evType == "vse-attestation-package" {
		success, toProve, measurement = certlib.ValidateInternalEvidence(pubKey, ep, policyPool, purpose)
		if !success {
			fmt.Printf("ValidateRequestAndObtainToken: ValidateInternalEvidence failed\n")
			return false, nil
		}
	} else if evType == "sev-platform-package" {
		success, toProve, measurement = certlib.ValidateSevEvidence(pubKey, ep, policyPool, purpose)
		if !success {
			fmt.Printf("ValidateRequestAndObtainToken: ValidateSevEvidence failed\n")
			return false, nil
		}
	} else if evType == "oe-evidence" {
		success, toProve, measurement = certlib.ValidateOeEvidence(pubKey, ep, policyPool, purpose)
		if !success {
			fmt.Printf("ValidateRequestAndObtainToken: ValidateOeEvidence failed\n")
			return false, nil
		}
	} else if evType == "gramine-evidence" {
		if extendedGramine {
			success, toProve, measurement = certlib.ValidateExtendedGramineEvidence(pubKey, ep, policyPool, purpose)
			if !success {
				fmt.Printf("ValidateRequestAndObtainToken: ValidateExtendedGramineEvidence failed\n")
				return false, nil
			}
		} else {
			success, toProve, measurement = certlib.ValidateGramineEvidence(pubKey, ep, policyPool, purpose)
			if !success {
				fmt.Printf("ValidateRequestAndObtainToken: ValidateGramineEvidence failed\n")
				return false, nil
			}
		}
	} else if evType == "keystone-evidence" {
		success, toProve, measurement = certlib.ValidateKeystoneEvidence(pubKey, ep, policyPool, purpose)
		if !success {
			fmt.Printf("ValidateRequestAndObtainToken: ValidateKeystoneEvidence failed\n")
			return false, nil
		}
	} else if evType == "islet-evidence" {
		success, toProve, measurement = certlib.ValidateIsletEvidence(pubKey, ep, policyPool, purpose)
		if !success {
			fmt.Printf("ValidateRequestAndObtainToken: ValidateIsletEvidence failed\n")
			return false, nil
		}
	} else {
		fmt.Printf("ValidateRequestAndObtainToken: Invalid Evidence type: %s\n", evType)
		return false, nil
	}

	// Produce Artifact
	var artifact []byte = nil
	if toProve == nil || toProve.Subject == nil || toProve.Subject.Key == nil ||
		toProve.Subject.Key.KeyName == nil {
		fmt.Printf("ValidateRequestAndObtainToken: toProve check failed\n")
		if toProve != nil {
			certlib.PrintVseClause(toProve)
			fmt.Printf("\n")
		}
		return false, nil
	}
	if policyCert == nil {
		fmt.Printf("ValidateRequestAndObtainToken: policyCert is nil\n")
		return false, nil
	}
	if privKey == nil {
		fmt.Printf("ValidateRequestAndObtainToken: privatePolicyKey is nil\n")
		return false, nil
	}

	if purpose == "attestation" {
		artifact = certlib.ProducePlatformRule(privKey, policyCert,
			toProve.Subject.Key, duration)
		if artifact == nil {
			return false, nil
		}
	} else {
		var appOrgName string
		if measurement == nil {
			fmt.Printf("ValidateRequestAndObtainToken: measurement is nil\n")
			return false, nil
		}
		appOrgName = "Measured-" + hex.EncodeToString(measurement)
		sn = sn + 1
		org := "CertifierUsers"

		// Debug
		fmt.Printf("Enclave key is:\n")
		certlib.PrintKey(toProve.Subject.Key)
		fmt.Printf("\norg: %s, appOrgName: %s\n", org, appOrgName)

		cert := certlib.ProduceAdmissionCert(remoteIP, privKey, policyCert,
			toProve.Subject.Key, org, appOrgName, sn, duration)
		if cert == nil {
			fmt.Printf("ValidateRequestAndObtainToken: x509 certificate is nil\n")
			return false, nil
		}

		// Debug
		certlib.PrintX509Cert(cert)
		artifact = cert.Raw
		if artifact == nil {
			fmt.Printf("ValidateRequestAndObtainToken: Asn1 artifact is nil\n")
			return false, nil
		}
	}

	// DEBUG
	if artifact == nil {
		fmt.Printf("ValidateRequestAndObtainToken: why is the artifact nil?\n")
	}
	fmt.Printf("Artifact:\n")
	certlib.PrintBytes(artifact)
	fmt.Printf("\n")

	return true, artifact
}

func ValidateRequestAndObtainSealedKey(pubKey *certprotos.KeyMessage, privKey *certprotos.KeyMessage,
	policyPool *certlib.PolicyPool, evType string, purpose string, ep *certprotos.EvidencePackage) (bool, []byte) {

	// evidenceType should be "vse-attestation-package", "sev-platform-package"
	var toProve *certprotos.VseClause = nil
	var success bool

	if purpose != "key-provision" {
		fmt.Printf("ValidateRequestAndObtainSealedKey: purpose must be key-provision\n")
		return false, nil
	}

	if evType == "vse-attestation-package" {
		success, toProve, _ = certlib.ValidateInternalEvidence(pubKey, ep, policyPool, purpose)
		if !success {
			fmt.Printf("ValidateRequestAndObtainSealedKey: ValidateInternalEvidence failed\n")
			return false, nil
		}
	} else if evType == "sev-platform-package" {
		success, toProve, _ = certlib.ValidateSevEvidence(pubKey, ep, policyPool, purpose)
		if !success {
			fmt.Printf("ValidateRequestAndObtainSealedKey: ValidateSevEvidence failed\n")
			return false, nil
		}
	} else {
		fmt.Printf("ValidateRequestAndObtainSealedKey: Invalid Evidence type: %s\n", evType)
		return false, nil
	}

	// Package policy key
	encapsulatingKey := toProve.Subject.Key

	edm := certprotos.EncapsulatedDataMessage{}
	alg := "aes-256-gcm"

	serializedPolicyKey, err := proto.Marshal(privKey)
	if err != nil {
		fmt.Printf("ValidateRequestAndObtainSealedKey: Can't serialize policy key\n")
		return false, nil
	}
	if !certlib.EncapsulateData(encapsulatingKey, alg, serializedPolicyKey, &edm) {
		fmt.Printf("ValidateRequestAndObtainSealedKey: Can't EncapsulateData\n")
		return false, nil
	}

	serializedEncapsulatedDataMessage, err := proto.Marshal(&edm)
	if err != nil {
		fmt.Printf("ValidateRequestAndObtainSealedKey: Can't marshal EncapsulateData\n")
		return false, nil
	}
	return true, serializedEncapsulatedDataMessage
}

// Procedure is:
//      read a message
//      evaluate the trust assertion
//      if it succeeds,
//            sign a cert
//            save the proof, action and cert info in the transaction files
//            save net infor for forensics
//      if it fails
//            save net infor for forensics
//      if logging is enabled, log event, request and response
func certifierServiceThread(conn net.Conn, client string) {

	b := certlib.SizedSocketRead(conn)
	if b == nil {
		logEvent("Can't read request", nil, nil)
		return
	}

	request := &certprotos.TrustRequestMessage{}
	err := proto.Unmarshal(b, request)
	if err != nil {
		fmt.Println("certifierServiceThread: Failed to decode request", err)
		logEvent("Can't unmarshal request", nil, nil)
		return
	}

	// Debug
	fmt.Printf("certifierServiceThread: Trust request received:\n")
	certlib.PrintTrustRequest(request)

	// Prepare response
	succeeded := "succeeded"
	failed := "failed"

	response := certprotos.TrustResponseMessage{}
	response.RequestingEnclaveTag = request.RequestingEnclaveTag
	response.ProvidingEnclaveTag = request.ProvidingEnclaveTag

	var remoteIP string
	if remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		remoteIP = remoteAddr.IP.String()
	}
	outcome, artifact := ValidateRequestAndObtainToken(remoteIP, publicPolicyKey, privatePolicyKey,
		&policyPool, request.GetSubmittedEvidenceType(), request.GetPurpose(),
		request.Support)

	if outcome {
		response.Status = &succeeded
		response.Artifact = artifact
	} else {
		response.Status = &failed
	}

	// Debug
	fmt.Printf("Sending response\n")
	certlib.PrintTrustReponse(&response)
	fmt.Printf("\n")

	// send response
	rb, err := proto.Marshal(&response)
	if err != nil {
		logEvent("Couldn't marshall request", b, nil)
		return
	}
	if !certlib.SizedSocketWrite(conn, rb) {
		fmt.Printf("SizedSocketWrite failed (2)\n")
		return
	}
	if response.Status != nil && *response.Status == "succeeded" {
		logEvent("Successful request", b, rb)
	} else {
		logEvent("Failed request", b, rb)
	}
	return
}

func keyServiceThread(conn net.Conn, client string) {

	b := certlib.SizedSocketRead(conn)
	if b == nil {
		logEvent("Can't read request", nil, nil)
		return
	}

	request := &certprotos.KeyRequestMessage{}
	err := proto.Unmarshal(b, request)
	if err != nil {
		fmt.Println("keyServiceThread: Failed to decode request", err)
		logEvent("Can't unmarshal request", nil, nil)
		return
	}

	// Debug
	fmt.Printf("keyServiceThread: Key request received:\n")
	certlib.PrintKeyRequestMessage(request)

	// Prepare response
	succeeded := "succeeded"
	failed := "failed"

	response := certprotos.KeyResponseMessage{}
	response.RequestingEnclaveTag = request.RequestingEnclaveTag
	response.ProvidingEnclaveTag = request.ProvidingEnclaveTag

	outcome, artifact := ValidateRequestAndObtainSealedKey(publicPolicyKey, privatePolicyKey,
		&policyPool, request.GetSubmittedEvidenceType(), "key-provision",
		request.Support)

	if outcome {
		response.Status = &succeeded
		response.Artifact = artifact
	} else {
		response.Status = &failed
	}

	// Debug
	fmt.Printf("Sending response\n")
	certlib.PrintKeyResponseMessage(&response)
	fmt.Printf("\n")

	// send response
	rb, err := proto.Marshal(&response)
	if err != nil {
		logEvent("Couldn't marshall request", b, nil)
		return
	}
	if !certlib.SizedSocketWrite(conn, rb) {
		fmt.Printf("SizedSocketWrite failed (2)\n")
		return
	}
	if response.Status != nil && *response.Status == "succeeded" {
		logEvent("Successful request", b, rb)
	} else {
		logEvent("Failed request", b, rb)
	}
	return
}

//	------------------------------------------------------------------------------------

func ProcessRequest(serverAddr string, req []byte) []byte {

	// Open socket, send request, get response.
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		fmt.Printf("ProcessRequest: open connection to key server\n")
		return nil
	}
	if !certlib.SizedSocketWrite(conn, req) {
		fmt.Printf("ProcessRequest: Can't send request\n")
		return nil
	}
	resp := certlib.SizedSocketRead(conn)
	conn.Close()
	return resp
}

func NegotiateProvisionRequest(serverAddr string, krm *certprotos.KeyRequestMessage, krr *certprotos.KeyResponseMessage) bool {

	serializedRequest, err := proto.Marshal(krm)
	if err != nil {
		fmt.Printf("NegotiateProvisionRequest: Can't marshal request\n")
		return false
	}

	resp := ProcessRequest(serverAddr, serializedRequest)
	if resp == nil {
		fmt.Printf("NegotiateProvisionRequest: ProcessRequest failed\n")
		return false
	}
	err = proto.Unmarshal(resp, krr)
	if err != nil {
		fmt.Printf("NegotiateProvisionRequest: Can't unmarshal response\n")
		return false
	}
	return true
}

func FillEvidenceList(enType string, el *certprotos.EvidenceList) bool {
	// Only simulated-enclave and sev-enclave supported now
	//
	// For:simulated-enclave:
	//      attestEndorsementFile
	//      signed_platform_says_attest_key_is_trusted, type: signed-claim
	// For sev:
	//      ark, ask and vcek certs, type: cert

	if enType == "simulated-enclave" {
		serializedPlatformEndorsement, err := os.ReadFile(*attestEndorsementFile)
		if err != nil {
			fmt.Printf("FillEvidenceList: Can't read endorsement\n")
			return false
		}
		ssc := "signed-claim"
		ev := certprotos.Evidence{}
		ev.EvidenceType = &ssc
		ev.SerializedEvidence = serializedPlatformEndorsement
		el.Assertion = append(el.Assertion, &ev)
	} else if enType == "sev-enclave" {
		arkCert, err := os.ReadFile(*arkFile)
		if err != nil {
			fmt.Printf("FillEvidenceList: Can't read ark cert\n")
			return false
		}
		ssc := "cert"
		ev := certprotos.Evidence{}
		ev.EvidenceType = &ssc
		ev.SerializedEvidence = arkCert
		el.Assertion = append(el.Assertion, &ev)
		askCert, err := os.ReadFile(*askFile)
		if err != nil {
			fmt.Printf("FillEvidenceList: Can't read ask cert\n")
			return false
		}
		ev = certprotos.Evidence{}
		ev.EvidenceType = &ssc
		ev.SerializedEvidence = askCert
		el.Assertion = append(el.Assertion, &ev)
		vcekCert, err := os.ReadFile(*vcekFile)
		if err != nil {
			fmt.Printf("FillEvidenceList: Can't read vcek cert\n")
			return false
		}
		ev = certprotos.Evidence{}
		ev.EvidenceType = &ssc
		ev.SerializedEvidence = vcekCert
		el.Assertion = append(el.Assertion, &ev)
	} else {
		fmt.Printf("FillEvidenceList: unsupported enclave type\n")
		return false
	}
	return true
}

func ProvisionKeys(serverAddr string) bool {

	rsaKey := certlib.MakeRsaKey(4096)
	if rsaKey == nil {
		fmt.Printf("ProvisionKeys: Can't generate transport key\n")
		return false
	}

	privateTransportKey := certprotos.KeyMessage{}
	if !certlib.GetInternalKeyFromRsaPrivateKey("transport-key", rsaKey, &privateTransportKey) {
		fmt.Printf("ProvisionKeys: Can't construct internal private transport key\n")
		return false
	}

	publicTransportKey := certlib.InternalPublicFromPrivateKey(&privateTransportKey)
	if publicTransportKey == nil {
		fmt.Printf("ProvisionKeys: Can't construct internal public transport key\n")
		return false
	}

	tn := certlib.TimePointNow()
	if tn == nil {
		fmt.Printf("ProvisionKeys: Can't get time now\n")
		return false
	}
	stn := certlib.TimePointToString(tn)

	ud := certprotos.AttestationUserData{}
	ud.EnclaveType = enclaveType
	ud.Time = &stn
	ud.EnclaveKey = publicTransportKey

	whatToSay, err := proto.Marshal(&ud)
	if err != nil {
		fmt.Printf("ProvisionKeys: Can't serialize user data\n")
		return false
	}

	at, err := certlib.TEEAttest(*enclaveType, whatToSay)
	if err != nil {
		fmt.Printf("ProvisionKeys: Attestation fails\n")
		return false
	}

	// Debug
	fmt.Printf("attestation size: %d\n", len(at))

	el := certprotos.EvidenceList{}
	if !FillEvidenceList(*enclaveType, &el) {
		fmt.Printf("ProvisionKeys: FillEvidenceList fails\n")
		return false
	}

	ep := certlib.ConstructPlatformEvidencePackage(*enclaveType, &el, at)
	if ep == nil {
		fmt.Printf("ProvisionKeys: Bad evidence package\n")
		return false
	}

	proverType := "vse-verifier"
	ep.ProverType = &proverType

	strRequestingEnclave := "requesting-enclave"
	strProvidingEnclave := "providing-enclave"

	// Send request and get response
	krm := certprotos.KeyRequestMessage{}

	krm.RequestingEnclaveTag = &strRequestingEnclave
	krm.ProvidingEnclaveTag = &strProvidingEnclave
	if *enclaveType == "simulated-enclave" {
		submittedEvType := "vse-attestation-package"
		krm.SubmittedEvidenceType = &submittedEvType
	} else if *enclaveType == "sev-enclave" {
		submittedEvType := "sev-platform-package"
		krm.SubmittedEvidenceType = &submittedEvType
	} else {
		fmt.Printf("ProvisionKeys: Unsupported enclave type\n")
		return false
	}
	krm.Support = ep

	// Debug
	certlib.PrintKeyRequestMessage(&krm)
	fmt.Printf("\n")

	krr := certprotos.KeyResponseMessage{}
	if !NegotiateProvisionRequest(serverAddr, &krm, &krr) {
		fmt.Printf("ProvisionKeys: Request negotiation failed\n")
		return false
	}

	// Debug
	certlib.PrintKeyResponseMessage(&krr)
	fmt.Printf("\n")

	if *krr.Status != "succeeded" || krr.Artifact == nil {
		fmt.Printf("ProvisionKeys: Key request failed\n")
		return false
	}

	// Artifact is an EncapsulatedDataMessage
	edm := certprotos.EncapsulatedDataMessage{}
	err = proto.Unmarshal(krr.Artifact, &edm)
	if err != nil {
		fmt.Printf("ProvisionKeys: Can't unmarshal encapsulated data message\n")
		return false
	}
	serializedPolicyKey := certlib.DecapsulateData(&privateTransportKey, &edm)
	if serializedPolicyKey == nil {
		fmt.Printf("ProvisionKeys: DecapsulateData failed\n")
		return false
	}

	// Make store, put policy key in it, and save it
	ps := certlib.NewPolicyStore(100)
	if ps == nil {
		fmt.Printf("ProvisionKeys: can't create policy store")
		return false
	}

	if !certlib.InsertOrUpdatePolicyStoreEntry(ps, "policy-key", "key", serializedPolicyKey) {
		fmt.Printf("ProvisionKeys: Can't insert policy key\n")
		return false
	}

	if !certlib.SavePolicyStore(*enclaveType, ps, *policyStoreFile) {
		fmt.Printf("ProvisionKeys: Can't save store\n")
		return false
	}

	return true
}

func SaveKeys() bool {
	serializedKey, err := os.ReadFile(*policyKeyFile)
	if err != nil {
		fmt.Println("SaveKeys: can't read key file, ", err)
		return false
	}

	ps := certlib.NewPolicyStore(100)
	if ps == nil {
		fmt.Printf("SaveKeys: can't create policy store")
		return false
	}

	privatePolicyKey = &certprotos.KeyMessage{}
	err = proto.Unmarshal(serializedKey, privatePolicyKey)
	if err != nil {
		fmt.Printf("SaveKeys: Can't unmarshal serialized policy key\n")
		return false
	}

	if !certlib.InsertOrUpdatePolicyStoreEntry(ps, "policy-key", "key", serializedKey) {
		fmt.Printf("SaveKeys: Can't insert policy key\n")
		return false
	}

	if !certlib.SavePolicyStore(*enclaveType, ps, *policyStoreFile) {
		fmt.Printf("SaveKeys: Can't save store\n")
		return false
	}

	// Debug
	/*
		psNew := new(certprotos.PolicyStoreMessage)
		if !certlib.RecoverPolicyStore(*enclaveType, *policyStoreFile, psNew) {
			fmt.Printf("SaveKeys: Can't recover store\n")
			return false
		}
		ent := certlib.FindPolicyStoreEntry(psNew, "policy-key", "key")
		if ent < 0 {
			fmt.Printf("SaveKeys: Can't find policy key in store\n")
			return false
		}
		recoveredSerializedKey := psNew.Entries[ent].Value
		privatePolicyKey2 := &certprotos.KeyMessage{}
		err = proto.Unmarshal(recoveredSerializedKey, privatePolicyKey2)
		if err != nil {
			fmt.Printf("SaveKeys: Can't unmarshal serialized policy key\n")
			return false
		}
		if !certlib.SameKey(privatePolicyKey, privatePolicyKey2) {
			fmt.Printf("SaveKeys: policy keys don't match\n")
			return false
		}
	*/

	return true
}

func keyServer(serverAddr string) {

	var sock net.Listener
	var err error
	var conn net.Conn

	// Listen for clients.
	fmt.Printf("Key server: listening\n")
	sock, err = net.Listen("tcp", serverAddr)
	if err != nil {
		fmt.Printf("Key server, listen error: ", err, "\n")
		return
	}

	// Service client connections.
	for {
		fmt.Printf("Key server: at accept\n")
		conn, err = sock.Accept()
		if err != nil {
			fmt.Printf("Key server: can't accept connection: %s\n", err.Error())
			continue
		}
		// Todo: maybe get client name and client IP for logging.
		var clientName string = "blah"
		go keyServiceThread(conn, clientName)
	}
}

func certifierServer(serverAddr string) {

	var sock net.Listener
	var err error
	var conn net.Conn

	// Listen for clients.
	fmt.Printf("server: listening\n")
	sock, err = net.Listen("tcp", serverAddr)
	if err != nil {
		fmt.Printf("Certifier server, listen error: ", err, "\n")
		return
	}

	// Service client connections.
	for {
		fmt.Printf("Certifier server: at accept\n")
		conn, err = sock.Accept()
		if err != nil {
			fmt.Printf("Certifier server: can't accept connection: %s\n", err.Error())
			continue
		}
		// Todo: maybe get client name and client IP for logging.
		var clientName string = "blah"
		go certifierServiceThread(conn, clientName)
	}
}

func main() {

	flag.Parse()

	var serverAddr string

	if *operation == "certifier-service" {
		// later this may turn into a TLS connection, we'll see
		if !initCertifierService(*getPolicyKeyFromSecureStore) {
			fmt.Printf("main: failed to initialize server\n")
			os.Exit(1)
		}
		serverAddr = *serverHost + ":" + *serverPort
		certifierServer(serverAddr)
		fmt.Printf("Certifier server done\n")
		os.Exit(0)
	} else if *operation == "provision-keys" {
		serverAddr = *keyServerHost + ":" + *keyServerPort
		if *enclaveType == "simulated-enclave" {
			blank := ""
			err := certlib.TEESimulatedInit(blank, *attestKeyFile, *measurementFile, *attestEndorsementFile)
			if err != nil {
				fmt.Printf("main: failed to initialize simulated enclave\n")
				os.Exit(1)
			}
		}
		if !ProvisionKeys(serverAddr) {
			fmt.Printf("main: failed to provision keys\n")
			os.Exit(1)
		}
		fmt.Printf("Keys provisioned\n")
		os.Exit(0)
	} else if *operation == "key-service" {
		if !initCertifierService(*getPolicyKeyFromSecureStore) {
			fmt.Printf("main: failed to initialize server\n")
			os.Exit(1)
		}
		serverAddr = *keyServerHost + ":" + *keyServerPort
		keyServer(serverAddr)
		fmt.Printf("Key server done\n")
		os.Exit(0)
	} else if *operation == "convert-key" {

		if *enclaveType == "simulated-enclave" {
			blank := ""
			err := certlib.TEESimulatedInit(blank, *attestKeyFile, *measurementFile, *attestEndorsementFile)
			if err != nil {
				fmt.Printf("main: failed to initialize simulated enclave\n")
				os.Exit(1)
			}
		}
		if !SaveKeys() {
			fmt.Printf("main: SaveKeys failed\n")
		}
		return
	} else {
		fmt.Printf("main: unsupported operation %s\n", *operation)
		return
	}
}
