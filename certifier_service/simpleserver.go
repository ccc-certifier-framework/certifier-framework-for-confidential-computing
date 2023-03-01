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
        certprotos "github.com/jlmucb/crypto/v2/certifier-framework-for-confidential-computing/certifier_service/certprotos"
        certlib "github.com/jlmucb/crypto/v2/certifier-framework-for-confidential-computing/certifier_service/certlib"
        //oeverify "github.com/jlmucb/crypto/v2/certifier-framework-for-confidential-computing/certifier_service/oeverify"
)

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

var privatePolicyKey *certprotos.KeyMessage = nil
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
var signedPolicy *certprotos.SignedClaimSequence = &certprotos.SignedClaimSequence {}
var originalPolicy *certprotos.ProvedStatements = &certprotos.ProvedStatements {}


// At init, we retrieve the policy key and the rules to evaluate
func initCertifierService() bool {
        // Debug
        fmt.Printf("Initializing CertifierService, Policy key file: %s, Policy cert file: %s\n", *policyKeyFile, *policyCertFile)

        if *enableLog {
                logging = initLog()
        }

        serializedKey, err := os.ReadFile(*policyKeyFile)
        if err != nil {
                fmt.Println("Simple_server: can't read key file, ", err)
                return false
        }

        serializedPolicyCert, err := os.ReadFile(*policyCertFile)
        if err != nil {
                fmt.Println("Simpleserver: can't read policy cert file, ", err)
                return false
        }
        policyCert, err = x509.ParseCertificate(serializedPolicyCert)
        if err != nil {
                fmt.Println("Simpleserver: Can't Parse policy cert, ", err)
                return false
        }

	privatePolicyKey := &certprotos.KeyMessage {}
        err = proto.Unmarshal(serializedKey, privatePolicyKey)
        if err != nil {
                fmt.Printf("SimpleServer: Can't unmarshal serialized policy key\n")
                return false
        }

        publicPolicyKey = certlib.InternalPublicFromPrivateKey(privatePolicyKey)
        if publicPolicyKey == nil {
                fmt.Printf("SimpleServer: Can't get public policy key\n")
                return false
        }

	// This should change to an InitPolicy call
        if policyFile == nil {
	        fmt.Printf("SimpleServer: No policy file\n")
		return false
	}

	// Read policy
	serializedPolicy, err := os.ReadFile(*policyFile)
	if err != nil {
	        fmt.Printf("SimpleServer: Can't read policy\n")
	        return false
	}

	err = proto.Unmarshal(serializedPolicy, signedPolicy)
	if err != nil {
	        fmt.Printf("SimpleServer: Can't unmarshal signed policy\n")
	        return false
	}

	if !certlib.InitAxiom(*publicPolicyKey, originalPolicy) {
                fmt.Printf("SimpleServer: Can't InitAxiom\n")
                return false
        }

	policyInitialized = certlib.InitPolicy(publicPolicyKey, signedPolicy, originalPolicy)

	if !policyInitialized {
		fmt.Printf("SimpleServer: Couldn't initialize policy\n")
		return false
	}

        if !certlib.InitSimulatedEnclave() {
                fmt.Printf("SimpleServer: Can't init simulated enclave\n")
                return false
        }
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

func ValidateRequestAndObtainToken(pubKey *certprotos.KeyMessage, privKey *certprotos.KeyMessage,
		evType string, purpose string, ep *certprotos.EvidencePackage) (bool, []byte) {

        // evidenceType should be "full-vse-support", "platform-attestation-only" or
        //      "oe-evidence" or "sev-platform-attestation-only" or "sev-platform-package"
	var toProve *certprotos.VseClause = nil
	var measurement []byte = nil
	var success bool

        if evType == "full-vse-support" {
		success, toProve, measurement = certlib.ValidateSimulatedEvidence(pubKey, ep, originalPolicy, purpose)
		if !success {
			fmt.Printf("ValidateRequestAndObtainToken: ValidateSimulatedEvidence failed\n")
			return false, nil
		}
        } else if evType == "platform-attestation-only" {
		success, toProve, measurement = certlib.ValidateSimulatedEvidence(pubKey, ep, originalPolicy, purpose)
		if !success {
			fmt.Printf("ValidateRequestAndObtainToken: ValidateSimulatedEvidence failed\n")
			return false, nil
		}
        } else if evType == "sev-platform-package" {
		success, toProve, measurement = certlib.ValidateSevEvidence(pubKey, ep, originalPolicy, purpose)
		if !success {
			fmt.Printf("ValidateRequestAndObtainToken: ValidateSevEvidence failed\n")
			return false, nil
		}
        } else if evType == "augmented-platform-attestation-only" {
        } else if evType == "oe-evidence" {
		success, toProve, measurement = certlib.ValidateOeEvidence(pubKey, ep, originalPolicy, purpose)
		if !success {
			fmt.Printf("ValidateRequestAndObtainToken: ValidateSevEvidence failed\n")
			return false, nil
		}
        } else {
                fmt.Printf("ValidateRequestAndObtainToken: Invalid Evidence type: %s\n", evType)
                return false, nil
        }

	// Produce Artifact
	var artifact []byte = nil
	if toProve.Subject == nil && toProve.Subject.Key == nil &&
			toProve.Subject.Key.KeyName == nil {
		fmt.Printf("ValidateRequestAndObtainToken: toProve check failed\n")
		certlib.PrintVseClause(toProve)
		fmt.Printf("\n")
		return false, nil
	}
	if purpose == "attestation" {
		artifact := certlib.ProducePlatformRule(privatePolicyKey, policyCert,
			toProve.Subject.Key, duration)
		if artifact == nil {
			return false, nil
		}
	} else {
		var appOrgName string
		if measurement != nil {
			appOrgName = "Measured-" + hex.EncodeToString(measurement)
		}
		sn = sn + 1
		org := "CertifierUsers"
		artifact := certlib.ProduceAdmissionCert(privatePolicyKey, policyCert,
			toProve.Subject.Key, org, appOrgName, sn, duration)
		if artifact == nil {
			return false, nil
		}
	}

  return true, artifact
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
func serviceThread(conn net.Conn, client string) {

	b := certlib.SizedSocketRead(conn)
	if b == nil {
                logEvent("Can't read request", nil, nil)
                return
	}

        request:= &certprotos.TrustRequestMessage{}
        err := proto.Unmarshal(b, request)
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

	outcome, artifact := ValidateRequestAndObtainToken(publicPolicyKey, privatePolicyKey,
		request.GetSubmittedEvidenceType(), request.GetPurpose(),
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
                logEvent("Failed Request", b, rb)
        }
        return
}

//	------------------------------------------------------------------------------------


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
