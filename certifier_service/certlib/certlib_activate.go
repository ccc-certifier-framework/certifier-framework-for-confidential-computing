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
	/*
	"bytes"
	"crypto/ecdsa"
	*/
	"crypto/rand"
	/*
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	 */
	"crypto/x509"
	//"errors"
	"fmt"
	/*
	"math/big"
	"os"
	 */

	certprotos "github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing/certifier_service/certprotos"
	tpmverify "github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing/certifier_service/tpmverify"
	"google.golang.org/protobuf/proto"
)

//      ------------------------------------------------------------------------

/*
 * message quote_certification_request {
 *   optional string requesting_enclave_tag  = 1;
 *   optional string providing_enclave_tag   = 2;
 *   optional bytes endorsement_cert         = 3;
 *   optional bytes endorsement_cert_chain   = 4;
 *   optional key_message quote_key          = 5;
 *   optional bytes quote_key_name           = 6;
 *   optional string quote_hash_alg          = 7;
 * };

 * message quote_certification_response {
 *   optional string status                  = 1; // "succeeded" or "failed"
 *   optional string hash_alg                = 2;
 *   optional bytes cred_blob                = 3;
 *   optional bytes encrypted_secret         = 4;
 *   optional string encrypting_alg          = 5;
 *   optional bytes encrypted_quote_cert     = 6;
 * };
 */

func PrintQuoteCertificationRequest(req *certprotos.QuoteCertificationRequest) {
	fmt.Printf("\nRequest:\n")
	fmt.Printf("Requesting Enclave Tag : %s\n", req.GetRequestingEnclaveTag())
	fmt.Printf("Providing Enclave Tag: %s\n", req.GetProvidingEnclaveTag())
	if req.QuoteHashAlg != nil {
		fmt.Printf("Hash alg: %s\n", *req.QuoteHashAlg)
	} else {
		fmt.Printf("No quote alg\n")
	}
	fmt.Printf("Endorsement Cert\n")
	PrintBytes(req.EndorsementCert)
	fmt.Printf("\n")
	fmt.Printf("Endorsement Cert Chain\n")
	PrintBytes(req.EndorsementCertChain)
	fmt.Printf("\n")
	fmt.Printf("Quote Key:\n")
	PrintKey(req.QuoteKey)
	fmt.Printf("\n")
	fmt.Printf("Quote Key name:\n")
	PrintBytes(req.QuoteKeyName)
	fmt.Printf("\n")

	fmt.Printf("\n")
}

func PrintQuoteCertificationResponse(res *certprotos.QuoteCertificationResponse) {
	// Status
	fmt.Printf("\nResponse:\n")
	fmt.Printf("Status: %s\n", res.GetStatus())
	if res.HashAlg != nil {
		fmt.Printf("Hash alg: %s\n", *res.HashAlg)
	} else {
		fmt.Printf("No quote alg\n")
	}
	if res.EncryptingAlg!= nil {
		fmt.Printf("Encrypting alg: %s\n", *res.EncryptingAlg)
	} else {
		fmt.Printf("No quote alg\n")
	}
	fmt.Printf("Cred blob\n")
	PrintBytes(res.CredBlob)
	fmt.Printf("\n")
	fmt.Printf("Encrypted Secret\n")
	PrintBytes(res.EncryptedSecret)
	fmt.Printf("\n")
	fmt.Printf("Encrypt Cert\n")
	PrintBytes(res.EncryptedQuoteCert)
	fmt.Printf("\n")
	fmt.Printf("\n")
}

func FillAndSerializeQuoteFailure(res *certprotos.QuoteCertificationResponse) []byte {
	*res.Status = "failed"
	serializedResponse, _ := proto.Marshal(res)
	return serializedResponse
}

func SameRoot(c []byte, r []byte) bool {
	return true
}

func CheckCertChain(bufSeq *certprotos.BufferSequence, rootCert []byte) (bool, *certprotos.KeyMessage) {
	var lastKey *certprotos.KeyMessage = nil
	return true, lastKey
}

 func ProcessActivationRequest(serializedRequest []byte, remoteIP string, roots *certprotos.BufferSequence, pubKey *certprotos.KeyMessage, policyCert *x509.Certificate, privKey *certprotos.KeyMessage) (bool, []byte) {

	request := &certprotos.QuoteCertificationRequest{}
	response := &certprotos.QuoteCertificationResponse{}
	err := proto.Unmarshal(serializedRequest, request)
	if err != nil {
		fmt.Println("activateServiceThread: Failed to decode request", err)
                return false, FillAndSerializeQuoteFailure(response)
	}

	// Debug
	fmt.Printf("activateServiceThread: Trust request received:\n")
	PrintQuoteCertificationRequest(request)

	err = proto.Unmarshal(serializedRequest, response)
	if err != nil {
		fmt.Printf("Can't unmarshal request\n")
	}

	// deserialize Endorsement cert chain
	certChain := &certprotos.BufferSequence{}
	err = proto.Unmarshal(request.EndorsementCertChain, certChain)

	var root []byte = nil
	for j := 0; j < len(roots.Block); j++ {
		blk := roots.Block[j]
		PrintBytes(blk)
		if SameRoot(certChain.Block[0], blk) {
			root = blk
			break;
		}
	}

	if root == nil {
		fmt.Println("activateServiceThread: no trusted root", err)
                return false, FillAndSerializeQuoteFailure(response)
	}

	s, lastKey := CheckCertChain(certChain, root)
	if  !s {
		fmt.Printf("activateServiceThread: cert chain does not verify")
                return false, FillAndSerializeQuoteFailure(response)
	}

	PrintKey(lastKey)
	// now check endorsement cert signature

        iv := make([]byte, 16)
        _, err = rand.Read(iv)
        if err != nil {
                fmt.Printf("ProcessActivationRequest: Can't generate iv\n")
                return false, FillAndSerializeQuoteFailure(response)
        }
        key := make([]byte, 32)
        _, err = rand.Read(key)
        if err != nil {
                fmt.Printf("ProcessActivationRequest: Can't generate\n")
                return false, FillAndSerializeQuoteFailure(response)
        }
	PrintBytes(iv)
	PrintBytes(key)

	s, credBlob, encryptedSecret := tpmverify.TpmMakeCredential(*request.QuoteHashAlg,
		request.QuoteKeyName, request.EndorsementCert, key)
	if !s {
                fmt.Printf("ProcessActivationRequest: MakeCredential\n")
                return false, FillAndSerializeQuoteFailure(response)
	}
	PrintBytes(credBlob)
	PrintBytes(encryptedSecret)

	encryptingAlg := "aes-256-gcm"

	// Make DER cert for quote key and sign it with policy key
	cert := ProduceAdmissionCert(remoteIP, privKey, policyCert, request.QuoteKey, "quote-key", "", uint64(5), 365.0*86400)
	if cert == nil {
	}

	// Serialize Cert
	serializedCert := X509ToAsn1(cert)
	if serializedCert == nil {
	}

	// Encrypt the DER cert using the credential
        encryptedCert:= GeneralAuthenticatedEncrypt(encryptingAlg, serializedCert, key, iv)
        if encryptedCert == nil {
                fmt.Printf("ProcessActivationRequest: Can't AuthenticatedEncrypt Data\n")
                return false, FillAndSerializeQuoteFailure(response)
        }

	*response.Status = "succeeded"
	*response.HashAlg= *request.QuoteHashAlg
	*response.EncryptingAlg = encryptingAlg
	response.CredBlob = credBlob
	response.EncryptedSecret = encryptedSecret
	response.EncryptedQuoteCert = encryptedCert

	// Debug
	fmt.Printf("activateServiceThread: Quote Certification Response\n")
	PrintQuoteCertificationResponse(response)

	// serialize it
	serializedResponse, _ := proto.Marshal(response)
	return true, serializedResponse
 }

//      ------------------------------------------------------------------------

