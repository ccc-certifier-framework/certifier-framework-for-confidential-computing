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
	"crypto/rsa"
	/*
	"crypto/sha256"
	"crypto/sha512"
	"math/big"
	"os"
	"errors"
	*/
	"crypto/rand"
	"crypto/x509"
	"fmt"

	certprotos "github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing/certifier_service/certprotos"
	tpmverify "github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing/certifier_service/tpmverify"
	"google.golang.org/protobuf/proto"
)

//      ------------------------------------------------------------------------

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
	fmt.Printf("Quote Key name: ")
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

func fillAndSerializeQuoteFailure(res *certprotos.QuoteCertificationResponse) []byte {
	*res.Status = "failed"
	serializedResponse, _ := proto.Marshal(res)
	return serializedResponse
}

// TODO: other key types
func getKeyFromCert(cert *x509.Certificate) (bool, *rsa.PublicKey) {
	PK, ok  := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false, nil
	}
	return true, PK
}

func CheckCertChain(tRoots *certprotos.BufferSequence, userChain *certprotos.BufferSequence, serializedEndorsementCert []byte) (bool, *x509.Certificate) {

        roots := x509.NewCertPool()
        intermediates := x509.NewCertPool()

	// add trusted roots
	for i := 0; i < len(tRoots.Block); i++ {
		nr := Asn1ToX509(tRoots.Block[i])
		// Debug
		fmt.Printf("Adding root:\n")
		PrintX509Cert(nr)
		roots.AddCert(nr)
	}

	// add intermediates
	for i := 0; i < len(userChain.Block); i++ {
		ni := Asn1ToX509(tRoots.Block[i])
		intermediates.AddCert(ni)
	}

	ec := Asn1ToX509(serializedEndorsementCert)
	if ec == nil {
                fmt.Printf("Can't deserialize endorsement\n");
		return false, nil
	}

	// Debug
	fmt.Printf("Calling verify for cert chain\n")

        opts := x509.VerifyOptions{
                Roots:         roots,
                Intermediates: intermediates,
                // DNSName:       "example.com", // Optional: checks if cert is valid for this host
        }

	fmt.Printf("FIX ME\n")
        _, err := ec.Verify(opts)
        if err != nil {
                fmt.Printf("Verification failed: %v\n", err)
		// return false, nil
                }
	return true, ec
}

/*
First Aid
	PK1, ok  := cert.PublicKey.(*rsa.PublicKey)
	PK2, ok := cert.PublicKey.(*rsa.PublicKey)
	CheckTimeRange(nb *string, na *string) bool
	hashed := sha256.Sum256(data)
	Time t := cert.NotBefore
	func (t Time) Day() int
	func (t Time) Hour() int
	func (t Time) Year() int
	func (t Time) Second() int
	func Now() Time
	monthInt := int(month)
 */

func ProcessActivationRequest(serializedRequest []byte, remoteIP string, roots *certprotos.BufferSequence, pubKey *certprotos.KeyMessage, policyCert *x509.Certificate, privKey *certprotos.KeyMessage) (bool, []byte) {

	// Debug
	fmt.Printf("activateServiceThread: Trust request received.\n")

	request := &certprotos.QuoteCertificationRequest{}
	response := &certprotos.QuoteCertificationResponse{}
	err := proto.Unmarshal(serializedRequest, request)
	if err != nil {
		fmt.Println("activateServiceThread: Failed to decode request", err)
                return false, fillAndSerializeQuoteFailure(response)
	}

	// Debug
	fmt.Printf("Request at certifier.\n")
	PrintQuoteCertificationRequest(request)

	err = proto.Unmarshal(serializedRequest, response)
	if err != nil {
		fmt.Printf("Can't unmarshal request\n")
	}

	// Deserialize Endorsement cert chain
	derCertChain := &certprotos.BufferSequence{}
	err = proto.Unmarshal(request.EndorsementCertChain, derCertChain)
	if err != nil {
		fmt.Printf("Can't unmarshal cert chain\n")
                return false, fillAndSerializeQuoteFailure(response)
	}

	// Debug
	// fmt.Printf("Deserialized cert chain\n")

	ok, endorsementCert :=  CheckCertChain(roots, derCertChain, request.EndorsementCert)
	if !ok {
		fmt.Printf("Cert chain does not verify\n")
                return false, fillAndSerializeQuoteFailure(response)
	}

	// Debug
	// fmt.Printf("Got endorsement cert\n")

	ok, endorsementKey := getKeyFromCert(endorsementCert)
	if !ok {
		fmt.Printf("Can't get endorsement key from cert\n")
                return false, fillAndSerializeQuoteFailure(response)
	}

	// Debug
	// fmt.Printf("Got endorsement key\n")

	keyName := "endorsement-key"
	internalEndorsementKey := &certprotos.KeyMessage{}
	if !GetInternalKeyFromRsaPublicKey(keyName, endorsementKey, internalEndorsementKey) {
		fmt.Printf("Can't get translated endorsement key\n")
                return false, fillAndSerializeQuoteFailure(response)
	}

	/*
	// Debug
	fmt.Printf("\nEndorsement key:\n")
	PrintKey(internalEndorsementKey)
	fmt.Printf("\n")
	 */

        iv := make([]byte, 12)
        _, err = rand.Read(iv)
        if err != nil {
                fmt.Printf("ProcessActivationRequest: Can't generate iv\n")
                return false, fillAndSerializeQuoteFailure(response)
        }
        key := make([]byte, 32)
        _, err = rand.Read(key)
        if err != nil {
                fmt.Printf("ProcessActivationRequest: Can't generate key\n")
                return false, fillAndSerializeQuoteFailure(response)
        }

	// Debug
	fmt.Printf("\niv: ")
	PrintBytes(iv)
	fmt.Printf("\n")
	fmt.Printf("key: ")
	PrintBytes(key)
	fmt.Printf("\n")

	s, credBlob, encryptedSecret := tpmverify.TpmMakeCredential(*request.QuoteHashAlg,
		request.QuoteKeyName, request.EndorsementCert, key)
	if !s {
                fmt.Printf("ProcessActivationRequest: MakeCredential\n")
                return false, fillAndSerializeQuoteFailure(response)
	}

	/*
	// Debug
	fmt.Printf("CertBlob:\n")
	PrintBytes(credBlob)
	fmt.Printf("\n")
	fmt.Printf("Encrypted Secret:\n")
	PrintBytes(encryptedSecret)
	fmt.Printf("\n")
	fmt.Printf("remoteIP: %s\n", remoteIP)
	 */

	// Make x509 cert for quote key and sign it with policy key
	cert := ProduceAdmissionCert(remoteIP, privKey, policyCert, request.QuoteKey, "quote-key", "TPM", uint64(5), 365.0 * 86400)
	if cert == nil {
                fmt.Printf("ProcessActivationRequest: Can't ProduceAdmissionCert\n")
                return false, fillAndSerializeQuoteFailure(response)
	}

	// Debug
	fmt.Printf("Generated quote cert\n")

	// Serialize Cert
	serializedQuoteCert := X509ToAsn1(cert)
	if serializedQuoteCert == nil {
                fmt.Printf("Can't serialize quote cert\n")
                return false, fillAndSerializeQuoteFailure(response)
	}

	// Encrypt the DER cert using the credential
	encryptingAlg := "aes-256-gcm"
        encryptedCert:= GeneralAuthenticatedEncrypt(encryptingAlg, serializedQuoteCert, key, iv)
        if encryptedCert == nil {
                fmt.Printf("ProcessActivationRequest: Can't AuthenticatedEncrypt Data\n")
                return false, fillAndSerializeQuoteFailure(response)
        }

	// Debug
	fmt.Printf("Unencrypted cert, %d bytes\n", len(serializedQuoteCert))
	fmt.Printf("Encrypted cert, %d bytes\n", len(encryptedCert))

	*response.Status = "succeeded"
	*response.HashAlg= *request.QuoteHashAlg
	*response.EncryptingAlg = encryptingAlg
	response.CredBlob = credBlob
	response.EncryptedSecret = encryptedSecret
	response.EncryptedQuoteCert = encryptedCert

	/*
	// Debug
	fmt.Printf("Quote Certification Response at certifier.\n")
	PrintQuoteCertificationResponse(response)
	 */

	// serialize response
	serializedResponse, _ := proto.Marshal(response)
	return true, serializedResponse
 }

//      ------------------------------------------------------------------------

