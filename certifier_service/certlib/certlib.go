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
	"encoding/asn1"
	"fmt"
	// "io"
	"math/big"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
	"google.golang.org/protobuf/proto"
	certprotos "github.com/jlmucb/crypto/v2/certifier-framework-for-confidential-computing/certifier_service/certprotos"
)

type PredicateDominance struct {
	Predicate string
	FirstChild *PredicateDominance
	Next *PredicateDominance
}

func Spaces(i int) {
	for j := 0; j < i; j++ {
		fmt.Printf(" ")
	}
}

func PrintDominanceNode (ind int, node *PredicateDominance) {
	if node == nil {
		fmt.Printf("\n")
		return
	}
	Spaces(ind)
	fmt.Printf("Node predicate: %s\n", node.Predicate)
}

func PrintDominanceTree(ind int, tree *PredicateDominance) {
	PrintDominanceNode (ind, tree)
	for n := tree.FirstChild; n != nil; n = n.Next {
		PrintDominanceTree(ind + 2, n)
	}
}

func FindNode(node *PredicateDominance, pred string) *PredicateDominance {
	if node.Predicate == pred {
		return node
	}
	for n := node.FirstChild; n != nil; n = n.Next {
		ret := FindNode(n, pred)
		if ret !=  nil {
			return ret
		}
		n = n.Next
	}
	return nil
}

func Insert(r *PredicateDominance, parent string, descendant string) bool {

	if r == nil {
		return false
	}

	ret :=  FindNode(r, parent)
	if ret == nil {
		return false
	}
	oldFirst :=  ret.FirstChild
	pd := &PredicateDominance {
		Predicate: descendant,
		FirstChild: nil,
		Next: oldFirst,
	}
	ret.FirstChild = pd
	return true
}

func IsChild(r *PredicateDominance, descendant string) bool {
	if r.Predicate == descendant {
		return true
	}
	for n := r.FirstChild; n != nil; n = n.Next {
		if IsChild(n, descendant) {
			return true
		}
	}
	return false
}

func Dominates(root *PredicateDominance, parent string, descendant string) bool {
	if parent == descendant {
		return true
	}
	r := FindNode(root, parent)
	if r == nil {
		return false
	}
	if IsChild(r, descendant) {
		return true
	}
	return false
}

func InitDominance(root *PredicateDominance) bool {
	root.Predicate = "is-trusted"
	root.FirstChild = nil
	root.Next = nil

	if !Insert(root, "is-trusted", "is-trusted-for-attestation") {
		return false;
	}
	if !Insert(root, "is-trusted", "is-trusted-for-authentication") {
		return false;
	}

	return true;
}

func PrintTimePoint(tp *certprotos.TimePoint) {
	if tp.GetYear() == 0 || tp.GetMonth() == 0 || tp.GetDay() == 0 || tp.GetHour() == 0 {
		return
	}
	fmt.Printf("%04d:%02d:%02dT%02d:%02d:%vZ",
		tp.GetYear(), tp.GetMonth(), tp.GetDay(),
		tp.GetHour(), tp.GetMinute(), tp.GetSeconds())
	return
}

func TimePointToString(tp *certprotos.TimePoint) string {
	s := fmt.Sprintf("%04d:%02d:%02dT%02d:%02d:%vZ",
		tp.GetYear(), tp.GetMonth(), tp.GetDay(),
		tp.GetHour(), tp.GetMinute(), tp.GetSeconds())
	return s
}

func TimePointNow() *certprotos.TimePoint {
	// func Date(year int, month Month, day, hour, min, sec, nsec int, loc *Location) Time
	t := time.Now()
	y := int32(t.Year())
	mo := int32(t.Month())
	d := int32(t.Day())
	h := int32(t.Hour())
	mi := int32(t.Minute())
	sec := float64(t.Second())
	tp := certprotos.TimePoint {
		Year: &y,
		Month: &mo,
		Day: &d,
		Hour: &h,
		Minute: &mi,
		Seconds: &sec,
	}
	return &tp
}

// if t1 is later than t2, return 1
// if t1 the same as t2, return 0
// if t1 is earlier than t2, return -1
func CompareTimePoints(t1 *certprotos.TimePoint, t2 *certprotos.TimePoint) int {
	if (t1.GetYear() > t2.GetYear()) {
		return 1
	}
	if (t1.GetYear() < t2.GetYear()) {
		return -1
	}
	if (t1.GetMonth() > t2.GetMonth()) {
		return 1
	}
	if (t1.GetMonth() < t2.GetMonth()) {
		return -1
	}
	if (t1.GetDay() > t2.GetDay()) {
		return 1
	}
	if (t1.GetDay() < t2.GetDay()) {
		return -1
	}
	if (t1.GetHour() > t2.GetHour()) {
		return 1
	}
	if (t1.GetHour() < t2.GetHour()) {
		return -1
	}
	if (t1.GetMinute() > t2.GetMinute()) {
		return 1
	}
	if (t1.GetMinute() < t2.GetMinute()) {
		return -1
	}
	if (t1.GetSeconds() > t2.GetSeconds()) {
		return 1
	}
	if (t1.GetSeconds() < t2.GetSeconds()) {
		return -1
	}
	return 0
}

func TimePointPlus(t *certprotos.TimePoint, d float64) *certprotos.TimePoint {
	tp := certprotos.TimePoint{}
	var yy int32 = t.GetYear()
	var mm int32 = t.GetMonth()
	var dd int32 = t.GetDay()
	var hh int32 = t.GetHour()
	var mmi int32 = t.GetMinute()
	var ss float64 = t.GetSeconds()
	tp.Year = &yy
	tp.Month = &mm
	tp.Day = &dd
	tp.Hour= &hh
	tp.Minute = &mmi
	tp.Seconds = &ss

	ns := t.GetSeconds() + d;
	ny := int32(ns / (365.0 * 86400))
	*tp.Year += ny
	ns -= float64(ny) * 365.0 * 86400
	nd := int32(ns / 86400)
	ns -= float64(nd) * 86400
	nh := int32(ns / 3600)
	ns -= float64(nh * 3600)
	nm := int32(ns / 60)
	ns -= float64(nm * 60)
	*tp.Seconds = ns
	nm += *tp.Minute
	i:= int32(nm / 60)
	*tp.Minute = nm - 60 * i
	nh += i + *tp.Hour
	i = int32(nh / 24)
	*tp.Hour = nh - 24 * i
	nd += i + *tp.Day
	var exitFlag = false
	mo:= *tp.Month
	for {
		if exitFlag {
			break
		}
		switch(1 + ((mo - 1) % 12)) {
		case 2:
			if nd <= 28 {
				exitFlag = true
				*tp.Day = nd
			} else {
				mo += 1
				nd -= 28
			}
		case 4, 6, 9, 11:
			if nd <= 30 {
				exitFlag = true
				*tp.Day = nd
			} else {
				mo += 1
				nd -= 30
			}
		case 1, 3, 5, 7, 8, 10, 12:
			if nd <= 31 {
				exitFlag = true
				*tp.Day = nd
			} else {
				mo += 1
				nd -= 31
			}
		}
	}
	ny =  (mo - 1) / 12
	*tp.Year += ny
	*tp.Month =  mo  -  ny * 12
	return &tp
}

func StringToTimePoint(s string) *certprotos.TimePoint {
	tp := certprotos.TimePoint{}
	var y int32 = 0
	var m int32
	var d int32
	var h int32
	var mi int32
	var sec float64 = 0.0
	fmt.Sscanf(s, "%04d:%02d:%02dT%02d:%02d:%v", &y, &m, &d, &h, &mi, &sec)
	tp.Year = &y
	tp.Month = &m
	tp.Day = &d
	tp.Hour= &h
	tp.Minute = &mi
	tp.Seconds = &sec
	return &tp
}

func GetRsaKeysFromInternal(k *certprotos.KeyMessage, pK *rsa.PrivateKey, PK *rsa.PublicKey) bool {
	PK.N = &big.Int{}
	PK.N.SetBytes(k.RsaKey.PublicModulus)
	t := big.Int{}
	t.SetBytes(k.RsaKey.PublicExponent)
	PK.E = int(t.Uint64())
	if k.RsaKey.PrivateExponent != nil {
		pK.D = &big.Int{}
		pK.D.SetBytes(k.RsaKey.PrivateExponent)
		pK.PublicKey = *PK
	} else {
		pK = nil
	}
	return true
}

func GetInternalKeyFromRsaPublicKey(name string, PK *rsa.PublicKey, km *certprotos.KeyMessage) bool {
	km.RsaKey = &certprotos.RsaMessage{}
	km.GetRsaKey().PublicModulus =  PK.N.Bytes()
	e := big.Int{}
	e.SetUint64(uint64(PK.E))
	km.GetRsaKey().PublicExponent=  e.Bytes()
	return true
}

func GetInternalKeyFromRsaPrivateKey(name string, pK *rsa.PrivateKey, km *certprotos.KeyMessage) bool {
	km.RsaKey = &certprotos.RsaMessage{}
	km.GetRsaKey().PublicModulus =  pK.PublicKey.N.Bytes()
	e := big.Int{}
	e.SetUint64(uint64(pK.PublicKey.E))
	km.GetRsaKey().PublicExponent=  e.Bytes()
	km.GetRsaKey().PrivateExponent =  pK.D.Bytes()
	return true
}

func InternalPublicFromPrivateKey(privateKey *certprotos.KeyMessage) *certprotos.KeyMessage {
	var kt string
	if privateKey.GetKeyType() == "rsa-1024-private" {
		kt = "rsa-1024-public"
	} else if privateKey.GetKeyType() == "rsa-2048-private" {
		kt = "rsa-2048-public"
	} else {
		return nil
	}
	if privateKey.GetRsaKey() == nil {
		return nil
	}
	publicKey := certprotos.KeyMessage{}
	publicKey.KeyType = &kt
	publicKey.KeyName = privateKey.KeyName
	publicKey.KeyFormat = privateKey.KeyFormat
	r := certprotos.RsaMessage {}
	publicKey.RsaKey = &r
	r.PublicModulus = privateKey.GetRsaKey().PublicModulus
	r.PublicExponent = privateKey.GetRsaKey().PublicExponent
	publicKey.Certificate = privateKey.Certificate
	publicKey.NotBefore = privateKey.NotBefore
	publicKey.NotAfter = privateKey.NotAfter
	return &publicKey
}

func MakeRsaKey(n int) *rsa.PrivateKey {
	rng := rand.Reader
	pK, err := rsa.GenerateKey(rng, n)
	if err != nil {
		return nil
	}
	return pK
}

func MakeVseRsaKey(n int) *certprotos.KeyMessage {
	pK :=  MakeRsaKey(n)
	if pK == nil {
		return nil
	}
	km := certprotos.KeyMessage {}
	var kf string
	if  n == 1024 {
		kf = "rsa-1024-private"
	} else if n == 2048 {
		kf = "rsa-2048-private"
	} else {
		return nil
	}
	km.KeyType  = &kf
	if GetInternalKeyFromRsaPrivateKey("generatedKey", pK, &km) == false {
		return nil
	}
	return &km
}

func RsaPublicEncrypt(r *rsa.PublicKey, in []byte) []byte {
	return nil
}

func RsaPrivateDecrypt(r *rsa.PrivateKey, in []byte) []byte {
	return nil
}

func RsaSha256Verify(r *rsa.PublicKey, in []byte, sig []byte) bool {
	hashed := sha256.Sum256(in)
	err:= rsa.VerifyPKCS1v15(r, crypto.SHA256, hashed[0:32], sig)
	if err == nil {
		return true
	}
	return false
}

func RsaSha256Sign(r *rsa.PrivateKey, in []byte) []byte {
	rng := rand.Reader
	hashed := sha256.Sum256(in)
	PrintBytes(hashed[0:32])
	signature, err := rsa.SignPKCS1v15(rng, r, crypto.SHA256, hashed[0:32])
	if err != nil {
		return nil
	}
	return signature
}

func FakeRsaSha256Verify(r *rsa.PublicKey, in []byte, sig []byte) bool {
	hashed := sha256.Sum256(in)
	encrypted := new(big.Int)
	e := big.NewInt(int64(r.E))
	payload := new(big.Int).SetBytes(sig)
	encrypted.Exp(payload, e, r.N)
	buf := encrypted.Bytes()

	if bytes.Equal(hashed[:], buf[len(buf)-32:]) {
		return true
	}
	return false
}


func Digest(in []byte) [32]byte {
	return sha256.Sum256(in)
}

func Pad(in []byte) []byte {
	var inLen int = len(in)
	var outLen int
	if inLen %  aes.BlockSize != 0 {
		outLen = ((inLen + aes.BlockSize - 1) / aes.BlockSize) * aes.BlockSize
	} else {
		outLen = inLen + aes.BlockSize
	}
	out:= make([]byte, outLen)
	for i := 0; i < inLen; i++ {
		out[i] = in[i]
	}
	out[inLen] = 0x80;
	for i := inLen + 1; i < outLen; i++ {
		out[i] = 0
	}
	return out
}

func Depad(in []byte) []byte {
	n := len(in)
	for i := n - 1; i >= 0; i-- {
		if in[i] == 0x80 {
			return in[0:i]
		}
	}
	return nil
}

func Encrypt(in []byte, key []byte, iv []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	padded := Pad(in)
	out :=  make([]byte, aes.BlockSize+len(padded))
	for i := 0; i < aes.BlockSize; i++ {
		out[i] = iv[i]
	}
	mode := cipher.NewCBCEncrypter(c, iv)
	mode.CryptBlocks(out[aes.BlockSize:], padded)
	return out
}

func Decrypt(in []byte, key []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	iv := in[0:aes.BlockSize]
	out :=  make([]byte, len(in))
	mode := cipher.NewCBCDecrypter(c, iv)
	mode.CryptBlocks(out, in[16:])
	return Depad(out)
}

func AuthenticatedEncrypt(in []byte, key []byte, iv []byte) []byte {
	// encrypt and hmac
	cip := Encrypt(in, key[0:32], iv)
	mac := hmac.New(sha256.New, key[32:])
	_, _ = mac.Write(cip)
	computedMac := mac.Sum(nil)
	out := make([]byte, (len(cip) + len(computedMac)))
	for i := 0; i < len(cip); i++ {
		out[i] = cip[i]
	}
	for i := 0; i < len(computedMac); i++ {
		out[i + len(cip)] = computedMac[i]
	}
	return out
}

func AuthenticatedDecrypt(in []byte, key []byte) []byte {
	// check hmac and decrypt
	mac := hmac.New(sha256.New, key[32:])
	n:= len(in) - 32
	fmt.Printf("n= %d\n", n)
	_, _ = mac.Write(in[0:n])
	computedMac := mac.Sum(nil)
	if !bytes.Equal(in[n:], computedMac) {
		return nil
	}
	dec := Decrypt(in[0:n], key[0:32])
	return dec
}

func SameMeasurement(m1 []byte, m2 []byte) bool {
	return bytes.Equal(m1, m2)
}

func SameKey(k1 *certprotos.KeyMessage, k2 *certprotos.KeyMessage) bool {
	if (k1.GetKeyType() != k2.GetKeyType()) {
		return false
	}
	if k1.GetKeyType() == "rsa-2048-private"  || k1.GetKeyType() == "rsa-2048-public" ||
		k1.GetKeyType() == "rsa-1024-private"  || k1.GetKeyType() == "rsa-1024-public" {
		return bytes.Equal(k1.RsaKey.PublicModulus, k2.RsaKey.PublicModulus) &&
			bytes.Equal(k1.RsaKey.PublicExponent, k2.RsaKey.PublicExponent)
	}
	return false
}

func SameEntity(e1 *certprotos.EntityMessage, e2 *certprotos.EntityMessage) bool {
	if e1.GetEntityType() != e2.GetEntityType() {
		return false
	}
	if  e1.GetEntityType() == "measurement" {
		return SameMeasurement(e1.GetMeasurement(), e2.GetMeasurement())
	}
	if  e1.GetEntityType() == "key" {
		return SameKey(e1.GetKey(), e2.GetKey())
	}
	return false
}

func SameVseClause(c1 *certprotos.VseClause, c2 *certprotos.VseClause) bool {
	if c1.Subject == nil ||  c2.Subject == nil {
		return false
	}
	if !SameEntity(c1.GetSubject(), c2.GetSubject()) {
		return false
	}
	if c1.GetVerb() != c2.GetVerb() {
		return false
	}
	if (c1.Object == nil && c2.Object != nil)  ||
		(c1.Object != nil &&  c2.Object == nil) {
		return false
	}
	if c1.Object != nil {
		if !SameEntity(c1.GetObject(), c2.GetObject()) {
			return false
		}
	}
	if (c1.GetClause() == nil  && c2.GetClause() != nil ) ||
		(c1.GetClause() != nil  && c2.GetClause() == nil) {
			return false
	}
	if c1.GetClause() != nil {
		return SameVseClause(c1.GetClause(), c2.GetClause())
	}
	return true
}

func MakeKeyEntity(k *certprotos.KeyMessage) *certprotos.EntityMessage {
	keye := certprotos.EntityMessage {}
	var kn string = "key"
	keye.EntityType = &kn
	keye.Key = k
	return &keye
}

func MakeMeasurementEntity(m []byte) *certprotos.EntityMessage {
	me := certprotos.EntityMessage {}
	measName := "measurement"
	me.EntityType = &measName
	me.Measurement = m
	return &me
}

func MakeUnaryVseClause(subject *certprotos.EntityMessage, verb *string) *certprotos.VseClause {
	vseClause := certprotos.VseClause{}
	vseClause.Subject = subject
	vseClause.Verb = verb
	return &vseClause
}

func MakeSimpleVseClause(subject *certprotos.EntityMessage, verb *string, object *certprotos.EntityMessage) *certprotos.VseClause {
	vseClause := certprotos.VseClause{}
	vseClause.Subject = subject
	vseClause.Verb = verb
	vseClause.Object = object
	return &vseClause
}

func MakeIndirectVseClause(subject *certprotos.EntityMessage, verb *string, cl *certprotos.VseClause) *certprotos.VseClause {
	vseClause := certprotos.VseClause{}
	vseClause.Subject = subject
	vseClause.Verb = verb
	vseClause.Clause=cl
	return &vseClause
}

func PrintBytes(b []byte) {
	for i := 0; i < len(b); i++  {
		fmt.Printf("%02x", b[i])
	}
	return
}

func PrintRsaKey(r *certprotos.RsaMessage) {
	if len(r.GetPublicModulus()) > 0 {
		fmt.Printf("Public Modulus : ")
		PrintBytes(r.GetPublicModulus())
		fmt.Printf("\n")
	}
	if len(r.GetPublicExponent()) > 0 {
		fmt.Printf("Public Exponent: ")
		PrintBytes(r.GetPublicExponent())
		fmt.Printf("\n")
	}
	if len(r.GetPrivateP()) > 0 {
		fmt.Printf("Private p      : ")
		PrintBytes(r.GetPrivateP())
		fmt.Printf("\n")
	}
	if len(r.GetPrivateQ()) > 0 {
		fmt.Printf("Private q      : ")
		PrintBytes(r.GetPrivateQ())
		fmt.Printf("\n")
	}
	if len(r.GetPrivateDp()) > 0 {
		fmt.Printf("Private dp     : ")
		PrintBytes(r.GetPrivateDp())
		fmt.Printf("\n")
	}
	if len(r.GetPrivateDq()) > 0 {
		fmt.Printf("Private dq     : ")
		PrintBytes(r.GetPrivateDq())
		fmt.Printf("\n")
	}

	return
}

func PrintKey(k *certprotos.KeyMessage) {
	fmt.Printf("RSA Key:\n")
	if k.GetKeyName() != "" {
		fmt.Printf("Key name  : %s\n", k.GetKeyName())
	}
	if k.GetKeyType() != "" {
		fmt.Printf("Key type  : %s\n", k.GetKeyType())
	}
	if k.GetKeyFormat() != "" {
		fmt.Printf("Key format: %s\n", k.GetKeyFormat())
	}
	if k.GetRsaKey() != nil {
		PrintRsaKey(k.GetRsaKey() )
	}
	return
}

func PrintKeyDescriptor(k *certprotos.KeyMessage) {
	if k.GetKeyType() == "" {
		return
	}

	if k.GetKeyType() == "rsa-2048-private" || k.GetKeyType() == "rsa-2048-public" ||
		k.GetKeyType() == "rsa-1024-private" || k.GetKeyType() == "rsa-1024-public" {
		fmt.Printf("Key[rsa, ")
		if k.GetKeyName() != "" {
			fmt.Printf("%s, ", k.GetKeyName())
		}
		if k.GetRsaKey() != nil {
			PrintBytes(k.GetRsaKey().GetPublicModulus()[0:20])
		}
		fmt.Printf("]")
	}
	return
}

func PrintEntityDescriptor(e *certprotos.EntityMessage) {
	if e.GetEntityType() == "measurement" {
		fmt.Printf("Measurement[")
		PrintBytes(e.GetMeasurement())
		fmt.Printf("]\n")
	}
	if e.GetEntityType() == "key" {
		PrintKeyDescriptor(e.GetKey())
	}
	return
}

func PrintVseClause(c *certprotos.VseClause) {
	if c.GetSubject() != nil {
		PrintEntityDescriptor(c.GetSubject())
	}
	if c.GetVerb() != "" {
		fmt.Printf(" %s ", c.GetVerb())
	}
	if c.GetObject() != nil {
		PrintEntityDescriptor(c.GetObject())
	}
	if c.GetClause() != nil {
		PrintVseClause(c.GetClause())
	}
	return
}

func PrintClaim(c *certprotos.ClaimMessage) {
	if c.GetClaimFormat() != "" {
		fmt.Printf("Claim format    : %s\n", c.GetClaimFormat())
	}
	if c.GetClaimDescriptor() != "" {
		fmt.Printf("Claim descriptor: %s\n", c.GetClaimDescriptor())
	}
	if c.GetNotBefore() != "" {
		fmt.Printf("Not before      : %s\n", c.GetNotBefore())
	}
	if c.GetNotAfter() != "" {
		fmt.Printf("Not after       : %s\n", c.GetNotAfter())
	}
	if c.GetSerializedClaim() != nil {
		fmt.Printf("Serialized claim: ")
		PrintBytes(c.GetSerializedClaim())
		fmt.Printf("\n")
	}
	return
}

func PrintAttestationUserData(sr *certprotos.AttestationUserData) {
	if sr.EnclaveType != nil {
		fmt.Printf("Enclave type: %s\n", *sr.EnclaveType)
	}
	if sr.Time!= nil {
		fmt.Printf("Time signed : %s\n", *sr.Time)
	}
	if sr.EnclaveKey != nil {
		PrintKey(sr.EnclaveKey)
	}
	return
}

func PrintVseAttestationReportInfo(info *certprotos.VseAttestationReportInfo) {
	if info.EnclaveType != nil {
		fmt.Printf("Enclave type: %s\n", *info.EnclaveType)
	}
	if info.VerifiedMeasurement != nil {
		fmt.Printf("Measurement : ")
		PrintBytes(info.VerifiedMeasurement)
	}
	if info.NotBefore!= nil  && info.NotAfter != nil {
		fmt.Printf("Valid between: %s and %s\n", *info.NotBefore, *info.NotAfter)
	}
	if info.UserData!= nil {
		fmt.Printf("User Data   : ")
		PrintBytes(info.UserData)
	}
	return
}

func PrintSignedReport(sr *certprotos.SignedReport) {
	if sr.ReportFormat != nil {
		fmt.Printf("Report format: %s\n", *sr.ReportFormat)
	}
	if sr.Report != nil {
		fmt.Printf("Report       : ")
		PrintBytes(sr.Report)
	}
	if sr.SigningAlgorithm != nil {
		fmt.Printf("Report format: %s\n", *sr.SigningAlgorithm)
	}
	if sr.SigningKey != nil {
		fmt.Printf("Signing key  : ")
		PrintKey(sr.SigningKey)
	}
	return
}

func PrintSignedClaim(s *certprotos.SignedClaimMessage) {
	if s.GetSerializedClaimMessage() != nil {
		fmt.Printf("Serialized claim: ")
		PrintBytes(s.GetSerializedClaimMessage())
		fmt.Printf("\n")
	}
	if s.GetSigningKey() != nil {
		PrintKey(s.GetSigningKey())
	}
	if s.GetSigningAlgorithm() != "" {
		fmt.Printf("Signing algoithm: %s\n", s.GetSigningAlgorithm())
	}
	if s.GetSignature() != nil {
		fmt.Printf("Signature       : ")
		PrintBytes(s.GetSignature())
		fmt.Printf("\n")
	}
	return
}

func PrintEntity(e *certprotos.EntityMessage) {
	if e.EntityType == nil {
		return
	}
	fmt.Printf("Entity type: %s\n", e.GetEntityType())
	if e.GetEntityType() == "key" {
		PrintKey(e.GetKey())
	}
	if e.GetEntityType() == "measurement" {
		PrintBytes(e.GetMeasurement())
	}
	return
}

func MakeClaim(serialized []byte, format string, desc string, nb string, na string) *certprotos.ClaimMessage {
	c := certprotos.ClaimMessage{}
	c.ClaimFormat = &format
	c.ClaimDescriptor = &desc
	c.NotBefore = &nb
	c.NotAfter = &na
	c.SerializedClaim = serialized
	return &c
}

func MakeSignedClaim(s *certprotos.ClaimMessage, k *certprotos.KeyMessage) *certprotos.SignedClaimMessage {
	if k.GetKeyType() == "" {
		return nil
	}
	sm := certprotos.SignedClaimMessage {}
	if k.GetKeyType() == "rsa-1024-private" {
		var ss string = "rsa-1024-sha256-pkcs-sign"
		sm.SigningAlgorithm =  &ss
	} else if k.GetKeyType() == "rsa-2048-private" {
		var ss string = "rsa-2048-sha256-pkcs-sign"
		sm.SigningAlgorithm =  &ss
	} else {
		return nil
	}

	psk :=  InternalPublicFromPrivateKey(k)
	sm.SigningKey = psk

	PK := rsa.PublicKey{}
	pK := rsa.PrivateKey{}
	if GetRsaKeysFromInternal(k, &pK, &PK) == false {
		return nil
	}
	// now sign it
	ser, err := proto.Marshal(s)
	if err != nil {
		return nil
	}
	sm.SerializedClaimMessage = ser
	sig := RsaSha256Sign(&pK, ser)
	if sig == nil {
		return nil
	}
	sm.Signature = sig
	return &sm
}

func VerifySignedClaim(c *certprotos.SignedClaimMessage, k *certprotos.KeyMessage) bool {
	PK := rsa.PublicKey{}
	pK := rsa.PrivateKey{}
	if GetRsaKeysFromInternal(k, &pK, &PK) == false {
		fmt.Printf("VerifySignedClaim: error 1\n")
		return false
	}

	cm := certprotos.ClaimMessage{}
	err := proto.Unmarshal(c.SerializedClaimMessage, &cm)
	if err != nil {
		fmt.Printf("VerifySignedClaim: error 2\n")
		return false
	}

	if cm.GetClaimFormat() != "vse-clause" && cm.GetClaimFormat() != "vse-attestation" {
		fmt.Printf("VerifySignedClaim: error 3\n")
		return false
	}

	tn := TimePointNow()
	tb := StringToTimePoint(cm.GetNotBefore())
	ta := StringToTimePoint(cm.GetNotAfter())
	if ta != nil && tb != nil {
		if CompareTimePoints(tb, tn) > 0 || CompareTimePoints(ta, tn) < 0 {
			fmt.Printf("VerifySignedClaim: error 4\n")
			return false
		}
	}

	// I remover the following hack:
	// || FakeRsaSha256Verify(&PK, c.GetSerializedClaimMessage(), c.GetSignature()) {
	if RsaSha256Verify(&PK, c.GetSerializedClaimMessage(), c.GetSignature()) {
		return true
	}
	return false
}

func VerifySignedAssertion(scm certprotos.SignedClaimMessage, k *certprotos.KeyMessage, vseClause *certprotos.VseClause) bool {
	// verify signed claim and extract vse clause
	if !VerifySignedClaim(&scm, k) {
		return false;
	}
	// extract clause
	cl_str := "vse-clause"

	cm := certprotos.ClaimMessage{}
	err := proto.Unmarshal(scm.GetSerializedClaimMessage(), &cm)
	if err != nil {
		return false
	}
	if cm.GetClaimFormat() == cl_str {
		err = proto.Unmarshal(cm.GetSerializedClaim(), vseClause)
		if err != nil {
			fmt.Printf("VerifySignedAssertion, Error 2\n")
			return false
		}
	} else {
		return false
	}
	return true
}

var privateAttestKey *certprotos.KeyMessage = nil
var publicAttestKey *certprotos.KeyMessage = nil
var rsaPublicAttestKey rsa.PublicKey
var rsaPrivateAttestKey rsa.PrivateKey
var sealingKey [64]byte
var sealIv [16]byte
var simulatedInitialized  bool = false

func InitSimulatedEnclave() bool {
	privateAttestKey = MakeVseRsaKey(2048)
	var tk  string = "simulatedAttestKey"
	privateAttestKey.KeyName = &tk
	publicAttestKey = InternalPublicFromPrivateKey(privateAttestKey)
	if publicAttestKey == nil {
		return false
	}
	if !GetRsaKeysFromInternal(privateAttestKey, &rsaPrivateAttestKey, &rsaPublicAttestKey) {
		return false
	}
	// now initialize sealing key and iv
	for i := 0; i < 64; i++ {
		sealingKey[i] = byte(i)
	}
	for i := 0; i < 16; i++ {
		sealIv[i] = byte(i + 17)
	}
	simulatedInitialized = true
	return true
}

func simultatedGetMeasurement(etype string, id string) []byte {
	m := make([]byte, 32)
	for i := 0; i < 32; i++ {
		m[i] = byte(i)
	}
	return m
}

func simultatedSeal(eType string, eId string, toSeal []byte) []byte {
	if !simulatedInitialized {
		return nil
	}
	return AuthenticatedEncrypt(toSeal, sealingKey[0:64], sealIv[0:16])
}

func simultatedUnseal(eType string, eId string, toUnseal []byte) []byte {
	if !simulatedInitialized {
		return nil
	}
	return AuthenticatedDecrypt(toUnseal, sealingKey[0:64])
}

func simultatedAttest(eType string, toSay []byte) []byte {
	if !simulatedInitialized {
		return nil
	}
	// toSay is a serilized attestation, turn it into a signed claim
	tn := TimePointNow()
	tf := TimePointPlus(tn, 365 * 86400)
	nb := TimePointToString(tn)
	na := TimePointToString(tf)
	cl1 := MakeClaim(toSay, "vse-attestation", "attestation", nb, na)
	serCl, err := proto.Marshal(cl1)
	if err != nil {
		return nil
	}
	sc := certprotos.SignedClaimMessage {}
	sc.SerializedClaimMessage = serCl
	sc.SigningKey = publicAttestKey
	var ss string = "rsa-2048-sha256-pkcs-sign"
	sc.SigningAlgorithm = &ss
	sig := RsaSha256Sign(&rsaPrivateAttestKey, toSay)
	sc.Signature = sig
	serSignedClaim, err := proto.Marshal(&sc)
	if err != nil {
		return nil
	}
	return serSignedClaim
}

func GetMeasurement(eType string, id string) []byte {
	if eType == "simulated-enclave" {
		return simultatedGetMeasurement(eType, id)
	}
	return nil
}

func Seal(eType string, eId string, toSeal []byte) []byte {
	if eType == "simulated-enclave" {
		return simultatedSeal(eType, eId, toSeal)
	}
	return nil
}

func Unseal(eType string, eId string, toUnseal []byte) []byte {
	if eType == "simulated-enclave" {
		return simultatedUnseal(eType, eId, toUnseal)
	}
	return nil
}

func Attest(eType string, toSay []byte) []byte {
	if eType == "simulated-enclave" {
		return simultatedAttest(eType, toSay)
	}
	return nil
}

func VerifyAttestation(eType string, attestBlob []byte, k *certprotos.KeyMessage) bool {
	sc := certprotos.SignedClaimMessage {}
	err := proto.Unmarshal(attestBlob, &sc)
	if err != nil {
		return false
	}
	return VerifySignedClaim(&sc, k)
}

func Asn1ToX509 (in []byte) *x509.Certificate {
	var cert x509.Certificate
	_, err := asn1.Unmarshal(in, &cert)
	if err != nil {
		return nil
	}
	return &cert
}

func X509ToAsn1(cert *x509.Certificate) []byte {
	out, err := asn1.Marshal(cert)
	if err != nil {
		return nil
	}
	return out
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

func ProduceAdmissionCert(issuerKey *certprotos.KeyMessage, issuerCert *x509.Certificate,
		subjKey *certprotos.KeyMessage, subjName string, subjOrg string,
		serialNumber uint64, durationSeconds float64) *x509.Certificate {

	dur := int64(durationSeconds * 1000 * 1000 * 1000)
	cert := x509.Certificate{
		SerialNumber: big.NewInt(int64(serialNumber)),
		Subject: pkix.Name {
			CommonName: subjName,
			Organization: []string{subjOrg},
		},
		NotBefore:	     time.Now(),
		NotAfter:	      time.Now().Add(time.Duration(dur)),
		IsCA:		  false,
		ExtKeyUsage:	   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:	      x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	spK := rsa.PrivateKey{}
	sPK := rsa.PublicKey{}
	if !GetRsaKeysFromInternal(subjKey, &spK, &sPK) {
		return nil
	}

	ipK := rsa.PrivateKey{}
	iPK := rsa.PublicKey{}
	if !GetRsaKeysFromInternal(issuerKey, &ipK, &iPK) {
		return nil
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &cert, issuerCert, &sPK, crypto.Signer(&ipK))
	if err != nil {
		fmt.Printf("error 3\n")
		fmt.Println(err)
		return nil
	}
	newCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil
	}
	return newCert
}

func GetIssuerNameFromCert(cert *x509.Certificate) *string {
	return &cert.Issuer.CommonName
}

func GetSubjectNameFromCert(cert *x509.Certificate) *string {
	return &cert.Subject.CommonName
}

func GetSubjectKey(cert *x509.Certificate) *certprotos.KeyMessage{
	var PK *rsa.PublicKey = cert.PublicKey.(*rsa.PublicKey)
	e := big.Int{}
	modulus := PK.N.Bytes()
	e.SetInt64(int64(PK.E))
	exp := e.Bytes()
	k := certprotos.KeyMessage{}
	k.KeyName = GetSubjectNameFromCert(cert)
	var kt string
	if len(modulus) == 128 {
		kt = "rsa-2048-public"
	} else if len(modulus) == 256 {
		kt = "rsa-2048-public"
	} else {
		return nil
	}
	k.KeyType = &kt
	r := certprotos.RsaMessage{}
	k.RsaKey = &r
	r.PublicModulus = modulus
	r.PublicExponent = exp
	return  &k
}

func GetIssuerKey(cert *x509.Certificate) *certprotos.KeyMessage{
	return nil
}

func VerifyAdmissionCert(policyCert *x509.Certificate, cert *x509.Certificate) bool {
	certPool := x509.NewCertPool()
	certPool.AddCert(policyCert)
	opts := x509.VerifyOptions{
		Roots:   certPool,
	}

	if _, err := cert.Verify(opts); err != nil {
		return false
	}
	return true
}

func PrintEvidence(ev *certprotos.Evidence) {
	fmt.Printf("Evidence type: %s\n", ev.GetEvidenceType())
	if ev.GetEvidenceType() == "signed-claim" {
		sc := certprotos.SignedClaimMessage{}
		err:= proto.Unmarshal(ev.SerializedEvidence, &sc)
		if err != nil {
			return
		}
		PrintSignedClaim(&sc)
	} else if ev.GetEvidenceType() == "signed-vse-attestation-report" {
		sr := certprotos.SignedReport{}
		err:= proto.Unmarshal(ev.SerializedEvidence, &sr)
		if err != nil {
			return
		}
		PrintSignedReport(&sr)
	} else if ev.GetEvidenceType() == "oe-attestation" {
		PrintBytes(ev.SerializedEvidence)
	} else if ev.GetEvidenceType() == "sev-attestation" {
		PrintBytes(ev.SerializedEvidence)
	} else {
		return
	}
}

func InitAxiom(pk certprotos.KeyMessage, ps *certprotos.ProvedStatements) bool {
	// add pk is-trusted to proved statenments
	ke := MakeKeyEntity(&pk)
	ist := "is-trusted"
	vc :=  MakeUnaryVseClause(ke, &ist)
	ps.Proved = append(ps.Proved, vc)
	return true
}

// Todo
func ConstructVseAttestClaim(attestKey *certprotos.KeyMessage, enclaveKey *certprotos.KeyMessage,
		measurement []byte) *certprotos.VseClause {
	return nil
}

// Todo
func VerifyReport(etype string, pk *certprotos.KeyMessage, serialized []byte) bool {
	return true;
}

// Todo
func CheckTimeRange(nb *string, na *string) bool {
	return true
}

func InitProvedStatements(pk certprotos.KeyMessage, evidenceList []*certprotos.Evidence,
		ps *certprotos.ProvedStatements) bool {
	if !InitAxiom(pk, ps) {
		return false
	}

	// Debug
	fmt.Printf("\nInitProvedStatements %d assertions\n", len(evidenceList))

	for i := 0; i < len(evidenceList); i++ {
		ev := evidenceList[i]
		if  ev.GetEvidenceType() == "signed-claim" {
			signedClaim := certprotos.SignedClaimMessage{}
			err := proto.Unmarshal(ev.SerializedEvidence, &signedClaim)
			if err != nil {
				fmt.Printf("Can't unmarshal serialized claim\n")
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
		} else if ev.GetEvidenceType() == "oe-assertion" {
			// call oeVerify here and construct the statement:
			//      enclave-key speaks-for measurement
			// from the return values.  Then add it to proved statements
			fmt.Printf("oe-verify not implemented\n")
			return false
		} else if ev.GetEvidenceType() == "sev-assertion" {
			fmt.Printf("sev-verify not implemented\n")
			return false
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
			}
		} else if ev.GetEvidenceType() == "cert" {
			fmt.Printf("Cert evidence type unimplemented\n")
			return false
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

// R1: If measurement is-trusted and key1 speaks-for measurement then key1 is-trusted-for-authentication.
func VerifyRule1(tree *PredicateDominance, c1 *certprotos.VseClause, c2 *certprotos.VseClause, c *certprotos.VseClause) bool {
	if c1.Subject == nil || c1.Verb == nil || c1.Object != nil || c1.Clause != nil {
		return false
	}
	if c1.GetVerb() != "is-trusted" {
		return false
	}
	if c1.Subject.GetEntityType() != "measurement" {
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
	if c.GetVerb() != "is-trusted-for-authentication" {
		return false
	}
	return SameEntity(c.Subject, c2.Subject)
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

	c3 := c2.Clause
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
		return false
	}

	return SameVseClause(c3, c)
}

// R6: if key1 is-trustedXXX and key1 says key2 speaks-for measurement then
//	key2 speaks-for measurement provided is-trustedXXX dominates is-trusted-for-attestation 
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
	if c3.Subject == nil || c3.Verb == nil || c3.Object == nil || c3.Clause != nil {
		return false
	}
	if c3.Subject.GetEntityType() != "key" {
		return false
	}
	if *c3.Verb != "speaks-for" {
		return false
	}
	if c3.Object.GetEntityType() != "measurement" {
		return false
	}
	if !Dominates(tree, *c1.Verb, "is-trusted-for-attestation") {
		return false
	}

	return SameVseClause(c3, c)
}

// R7: If measurement is-trusted and key1 speaks-for measurement then key1 is-trusted-for-attestation.
func VerifyRule7(tree *PredicateDominance, c1 *certprotos.VseClause, c2 *certprotos.VseClause, c *certprotos.VseClause) bool {
	if c1.Subject == nil || c1.Verb == nil || c1.Object != nil || c1.Clause != nil {
		return false
	}
	if c1.GetVerb() != "is-trusted" {
		return false
	}
	if c1.Subject.GetEntityType() != "measurement" {
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
		var s1  *certprotos.VseClause = p.Steps[i].S1
		var s2  *certprotos.VseClause = p.Steps[i].S2
		var c  *certprotos.VseClause = p.Steps[i].Conclusion
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
			return false
		}

	}
	return false
}

func PrintTrustRequest(req *certprotos.TrustRequestMessage) {
	fmt.Printf("\nRequest:\n")
	fmt.Printf("Requesting Enclave Tag : %s\n", req.GetRequestingEnclaveTag())
	fmt.Printf("Providing Enclave Tag: %s\n", req.GetProvidingEnclaveTag())
	if req.Purpose != nil {
		fmt.Printf("Purpose: %s\n", *req.Purpose)
	}
	if req.SubmittedEvidenceType != nil {
		fmt.Printf("\nSubmittedEvidenceType: %s\n", req.GetSubmittedEvidenceType())
	}

	fmt.Printf("Prover Type: %s\n\n", req.Support.GetProverType())
	// Support
	if req.Support != nil {
		for  i := 0; i < len(req.Support.FactAssertion); i++ {
			fmt.Printf("\nEvidence %d:\n", i)
			fmt.Printf("Evidence Type: %s\n", req.Support.FactAssertion[i].GetEvidenceType())
			if req.Support.FactAssertion[i].GetEvidenceType() == "signed-claim" {
				signedClaimMsg := certprotos.SignedClaimMessage {}
				err := proto.Unmarshal(req.Support.FactAssertion[i].GetSerializedEvidence(), &signedClaimMsg)
				if err != nil {
					return
				}
				PrintSignedClaim(&signedClaimMsg)
			} else if req.Support.FactAssertion[i].GetEvidenceType() == "oe_assertion" {
				PrintBytes(req.Support.FactAssertion[i].GetSerializedEvidence())
			}
			fmt.Printf("\n")
		}
	} else {
		fmt.Printf("Support is empty\n")
	}
	fmt.Printf("\n")
}

func PrintTrustReponse(res *certprotos.TrustResponseMessage) {
	// Status
	// RequestingEnclaveTag
	// ProvidingEnclaveTag
	// Artifact
	fmt.Printf("\nResponse:\n")
	fmt.Printf("Status: %s\n", res.GetStatus())
	fmt.Printf("Requesting Enclave Tag : %s\n", res.GetRequestingEnclaveTag())
	fmt.Printf("Providing Enclave Tag: %s\n", res.GetProvidingEnclaveTag())
	if res.Artifact != nil {
		fmt.Printf("Artifact: ")
		PrintBytes(res.Artifact)
		fmt.Printf("\n")
	}
	fmt.Printf("\n")
}

func GetVseFromSignedClaim(sc *certprotos.SignedClaimMessage) *certprotos.VseClause {
	claimMsg := certprotos.ClaimMessage {}
	err := proto.Unmarshal(sc.SerializedClaimMessage, &claimMsg)
	if err != nil {
		return nil
	}
	vseClause :=  certprotos.VseClause {}
	if claimMsg.GetClaimFormat() == "vse-clause" {
		err = proto.Unmarshal(claimMsg.SerializedClaim, &vseClause)
		if err != nil {
			return nil
		}
	} else {
		return nil
	}
	return &vseClause
}
