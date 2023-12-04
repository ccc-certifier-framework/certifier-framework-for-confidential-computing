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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	certprotos "github.com/vmware-research/certifier-framework-for-confidential-computing/certifier_service/certprotos"
	"google.golang.org/protobuf/proto"
	// oeverify   "github.com/vmware-research/certifier-framework-for-confidential-computing/certifier_service/oeverify"
)

//  --------------------------------------------------------------------

type PredicateDominance struct {
	Predicate  string
	FirstChild *PredicateDominance
	Next       *PredicateDominance
}

func Spaces(i int) {
	for j := 0; j < i; j++ {
		fmt.Printf(" ")
	}
}

func PrintDominanceNode(ind int, node *PredicateDominance) {
	if node == nil {
		fmt.Printf("\n")
		return
	}
	Spaces(ind)
	fmt.Printf("Node predicate: %s\n", node.Predicate)
}

func PrintDominanceTree(ind int, tree *PredicateDominance) {
	PrintDominanceNode(ind, tree)
	for n := tree.FirstChild; n != nil; n = n.Next {
		PrintDominanceTree(ind+2, n)
	}
}

func FindNode(node *PredicateDominance, pred string) *PredicateDominance {
	if node.Predicate == pred {
		return node
	}
	for n := node.FirstChild; n != nil; n = n.Next {
		ret := FindNode(n, pred)
		if ret != nil {
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

	ret := FindNode(r, parent)
	if ret == nil {
		return false
	}
	oldFirst := ret.FirstChild
	pd := &PredicateDominance{
		Predicate:  descendant,
		FirstChild: nil,
		Next:       oldFirst,
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
		return false
	}
	if !Insert(root, "is-trusted", "is-trusted-for-authentication") {
		return false
	}
	if !Insert(root, "is-trusted", "is-trusted-for-key-provision") {
		return false
	}

	return true
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
	tp := certprotos.TimePoint{
		Year:    &y,
		Month:   &mo,
		Day:     &d,
		Hour:    &h,
		Minute:  &mi,
		Seconds: &sec,
	}
	return &tp
}

// if t1 is later than t2, return 1
// if t1 the same as t2, return 0
// if t1 is earlier than t2, return -1
func CompareTimePoints(t1 *certprotos.TimePoint, t2 *certprotos.TimePoint) int {
	if t1.GetYear() > t2.GetYear() {
		return 1
	}
	if t1.GetYear() < t2.GetYear() {
		return -1
	}
	if t1.GetMonth() > t2.GetMonth() {
		return 1
	}
	if t1.GetMonth() < t2.GetMonth() {
		return -1
	}
	if t1.GetDay() > t2.GetDay() {
		return 1
	}
	if t1.GetDay() < t2.GetDay() {
		return -1
	}
	if t1.GetHour() > t2.GetHour() {
		return 1
	}
	if t1.GetHour() < t2.GetHour() {
		return -1
	}
	if t1.GetMinute() > t2.GetMinute() {
		return 1
	}
	if t1.GetMinute() < t2.GetMinute() {
		return -1
	}
	if t1.GetSeconds() > t2.GetSeconds() {
		return 1
	}
	if t1.GetSeconds() < t2.GetSeconds() {
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
	tp.Hour = &hh
	tp.Minute = &mmi
	tp.Seconds = &ss

	ns := t.GetSeconds() + d
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
	i := int32(nm / 60)
	*tp.Minute = nm - 60*i
	nh += i + *tp.Hour
	i = int32(nh / 24)
	*tp.Hour = nh - 24*i
	nd += i + *tp.Day
	var exitFlag = false
	mo := *tp.Month
	for {
		if exitFlag {
			break
		}
		switch 1 + ((mo - 1) % 12) {
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
	ny = (mo - 1) / 12
	*tp.Year += ny
	*tp.Month = mo - ny*12
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
	tp.Hour = &h
	tp.Minute = &mi
	tp.Seconds = &sec
	return &tp
}

func SamePoint(p1 *certprotos.PointMessage, p2 *certprotos.PointMessage) bool {
	if p1.X == nil || p1.Y == nil || p2.X == nil || p2.Y == nil {
		return false
	}
	return bytes.Equal(p1.X, p2.X) && bytes.Equal(p1.Y, p2.Y)
}

func GetEccKeysFromInternal(k *certprotos.KeyMessage) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	if k == nil || k.EccKey == nil {
		fmt.Printf("GetEccKeysFromInternal: no ecc key\n")
		return nil, nil, errors.New("EccKey")
	}
	if k.EccKey.PublicPoint == nil {
		fmt.Printf("GetEccKeysFromInternal: no public point\n")
		return nil, nil, errors.New("EccKey")
	}
	if k.EccKey.BasePoint == nil {
		fmt.Printf("GetEccKeysFromInternal: no base\n")
		return nil, nil, errors.New("no base point")
	}

	tX := new(big.Int).SetBytes(k.EccKey.PublicPoint.X)
	tY := new(big.Int).SetBytes(k.EccKey.PublicPoint.Y)

	if k.GetKeyType() == "ecc-384-public" {
		PK := &ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     tX,
			Y:     tY,
		}
		return nil, PK, nil
	} else if k.GetKeyType() == "ecc-384-private" {
		PK := &ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     tX,
			Y:     tY,
		}
		D := new(big.Int).SetBytes(k.EccKey.PrivateMultiplier)
		pK := &ecdsa.PrivateKey{
			PublicKey: *PK,
			D:         D,
		}
		return pK, PK, nil
	} else if k.GetKeyType() == "ecc-256-public" {
		PK := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     tX,
			Y:     tY,
		}
		return nil, PK, nil
	} else if k.GetKeyType() == "ecc-256-private" {
		PK := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     tX,
			Y:     tY,
		}
		D := new(big.Int).SetBytes(k.EccKey.PrivateMultiplier)
		pK := &ecdsa.PrivateKey{
			PublicKey: *PK,
			D:         D,
		}
		return pK, PK, nil
	} else {
		fmt.Printf("GetEccKeysFromInternal: Wrong key type %s\n", k.GetKeyType())
		return nil, nil, nil
	}
}

func GetInternalKeyFromEccPublicKey(name string, PK *ecdsa.PublicKey, km *certprotos.KeyMessage) bool {
	if PK.Curve == nil {
		fmt.Printf("No curve\n")
		return false
	}
	km.KeyName = &name
	format := "vse-key"
	km.KeyFormat = &format
	p := PK.Curve.Params()
	fmt.Printf("Bitsize: %d\n", p.BitSize)
	var ktype string
	var nm string

	byteSize := 1 + p.BitSize/8
	if p.BitSize == 256 {
		nm = "P-256"
		ktype = "ecc-256-public"
	} else if p.BitSize == 384 {
		nm = "P-384"
		ktype = "ecc-384-public"
	} else {
		fmt.Printf("GetInternalKeyFromEccPublicKey: unsupported key size (%d)\n", p.BitSize)
		return false
	}
	km.KeyType = &ktype
	if p.P == nil || p.B == nil || p.Gx == nil || p.Gy == nil || PK.X == nil || PK.Y == nil {
		return false
	}
	km.EccKey = new(certprotos.EccMessage)
	km.EccKey.CurveName = &nm

	km.EccKey.CurveP = make([]byte, byteSize)
	km.EccKey.CurveP = p.P.FillBytes(km.EccKey.CurveP)

	// A is -3
	t := new(big.Int)
	t.SetInt64(-3)
	a := new(big.Int)
	a.Add(t, p.P)

	km.EccKey.CurveA = make([]byte, byteSize)
	km.EccKey.CurveA = a.FillBytes(km.EccKey.CurveA)

	km.EccKey.CurveB = make([]byte, byteSize)
	km.EccKey.CurveB = p.B.FillBytes(km.EccKey.CurveB)

	km.EccKey.PublicPoint = new(certprotos.PointMessage)
	km.EccKey.PublicPoint.X = make([]byte, byteSize)
	km.EccKey.PublicPoint.Y = make([]byte, byteSize)
	km.EccKey.PublicPoint.X = PK.X.FillBytes(km.EccKey.PublicPoint.X)
	km.EccKey.PublicPoint.Y = PK.Y.FillBytes(km.EccKey.PublicPoint.Y)

	km.EccKey.BasePoint = new(certprotos.PointMessage)
	km.EccKey.BasePoint.X = make([]byte, byteSize)
	km.EccKey.BasePoint.Y = make([]byte, byteSize)
	km.EccKey.BasePoint.X = p.Gx.FillBytes(km.EccKey.BasePoint.X)
	km.EccKey.BasePoint.Y = p.Gy.FillBytes(km.EccKey.BasePoint.Y)
	return true
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
	km.KeyName = &name
	modLen := len(PK.N.Bytes())
	var kt string
	if modLen == 128 {
		kt = "rsa-1024-public"
	} else if modLen == 256 {
		kt = "rsa-2048-public"
	} else if modLen == 384 {
		kt = "rsa-3072-public"
	} else if modLen == 512 {
		kt = "rsa-4096-public"
	} else {
		return false
	}
	km.KeyType = &kt
	km.RsaKey = &certprotos.RsaMessage{}
	km.GetRsaKey().PublicModulus = PK.N.Bytes()
	e := big.Int{}
	e.SetUint64(uint64(PK.E))
	km.GetRsaKey().PublicExponent = e.Bytes()
	return true
}

func GetInternalKeyFromRsaPrivateKey(name string, pK *rsa.PrivateKey, km *certprotos.KeyMessage) bool {
	km.RsaKey = &certprotos.RsaMessage{}

	km.KeyName = &name
	modLen := len(pK.PublicKey.N.Bytes())
	var kt string
	if modLen == 128 {
		kt = "rsa-1024-private"
	} else if modLen == 256 {
		kt = "rsa-2048-private"
	} else if modLen == 384 {
		kt = "rsa-3072-private"
	} else if modLen == 512 {
		kt = "rsa-4096-private"
	} else {
		return false
	}
	km.KeyType = &kt

	km.GetRsaKey().PublicModulus = pK.PublicKey.N.Bytes()
	e := big.Int{}
	e.SetUint64(uint64(pK.PublicKey.E))
	km.GetRsaKey().PublicExponent = e.Bytes()
	km.GetRsaKey().PrivateExponent = pK.D.Bytes()
	return true
}

func InternalPublicFromPrivateKey(privateKey *certprotos.KeyMessage) *certprotos.KeyMessage {
	var kt string
	if privateKey.GetKeyType() == "rsa-1024-private" {
		kt = "rsa-1024-public"
	} else if privateKey.GetKeyType() == "rsa-2048-private" {
		kt = "rsa-2048-public"
	} else if privateKey.GetKeyType() == "rsa-3072-private" {
		kt = "rsa-3072-public"
	} else if privateKey.GetKeyType() == "rsa-4096-private" {
		kt = "rsa-4096-public"
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
	r := certprotos.RsaMessage{}
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
	pK := MakeRsaKey(n)
	if pK == nil {
		return nil
	}
	km := certprotos.KeyMessage{}
	var kf string
	if n == 1024 {
		kf = "rsa-1024-private"
	} else if n == 2048 {
		kf = "rsa-2048-private"
	} else if n == 3072 {
		kf = "rsa-3072-private"
	} else if n == 4096 {
		kf = "rsa-4096-private"
	} else {
		return nil
	}
	km.KeyType = &kf
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
	err := rsa.VerifyPKCS1v15(r, crypto.SHA256, hashed[0:32], sig)
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
	if inLen%aes.BlockSize != 0 {
		outLen = ((inLen + aes.BlockSize - 1) / aes.BlockSize) * aes.BlockSize
	} else {
		outLen = inLen + aes.BlockSize
	}
	out := make([]byte, outLen)
	for i := 0; i < inLen; i++ {
		out[i] = in[i]
	}
	out[inLen] = 0x80
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
	out := make([]byte, aes.BlockSize+len(padded))
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
	out := make([]byte, len(in))
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
		out[i+len(cip)] = computedMac[i]
	}
	return out
}

func AuthenticatedDecrypt(in []byte, key []byte) []byte {
	// check hmac and decrypt
	mac := hmac.New(sha256.New, key[32:])
	n := len(in) - 32
	fmt.Printf("n= %d\n", n)
	_, _ = mac.Write(in[0:n])
	computedMac := mac.Sum(nil)
	if !bytes.Equal(in[n:], computedMac) {
		return nil
	}
	dec := Decrypt(in[0:n], key[0:32])
	return dec
}

// Todo: implement the others
func GeneralAuthenticatedEncrypt(alg string, in []byte, key []byte, iv []byte) []byte {
	if alg == "aes-256-cbc-hmac-sha256" {
		return AuthenticatedEncrypt(in, key, iv)
	}
	if alg == "aes-256-gcm" {
		tagLen := 12

		k, err := aes.NewCipher(key)
		if err != nil {
			fmt.Printf("GeneralAuthenticatedEncrypt: can't aes NewCipher\n")
			return nil
		}
		gcm, err := cipher.NewGCM(k)
		if err != nil {
			fmt.Printf("GeneralAuthenticatedEncrypt: can't aes NewGCM\n")
			return nil
		}
		out := gcm.Seal(nil, iv[0:tagLen], in, nil)
		return append(iv, out...)
	}
	return nil
}

func GeneralAuthenticatedDecrypt(alg string, in []byte, key []byte) []byte {
	if alg == "aes-256-cbc-hmac-sha256" {
		return AuthenticatedDecrypt(in, key)
	}
	if alg == "aes-256-gcm" {
		tagLen := 12

		k, err := aes.NewCipher(key)
		if err != nil {
			fmt.Printf("GeneralAuthenticatedEncrypt: can't aes NewCipher\n")
			return nil
		}
		gcm, err := cipher.NewGCM(k)
		if err != nil {
			fmt.Printf("GeneralAuthenticatedEncrypt: can't aes NewGCM\n")
			return nil
		}

		iv := in[0:tagLen]
		out, err := gcm.Open(nil, iv, in[aes.BlockSize:], nil)
		if err != nil {
			fmt.Printf("GeneralAuthenticatedEncrypt: can't aes NewGCM\n")
			return nil
		}
		return out
	}
	return nil
}

func SameMeasurement(m1 []byte, m2 []byte) bool {
	return bytes.Equal(m1, m2)
}

func SameKey(k1 *certprotos.KeyMessage, k2 *certprotos.KeyMessage) bool {
	if k1.GetKeyType() != k2.GetKeyType() {
		return false
	}
	if k1.GetKeyType() == "rsa-2048-private" || k1.GetKeyType() == "rsa-2048-public" ||
		k1.GetKeyType() == "rsa-3072-private" || k1.GetKeyType() == "rsa-3072-public" ||
		k1.GetKeyType() == "rsa-4096-private" || k1.GetKeyType() == "rsa-4096-public" ||
		k1.GetKeyType() == "rsa-1024-private" || k1.GetKeyType() == "rsa-1024-public" {
		return bytes.Equal(k1.RsaKey.PublicModulus, k2.RsaKey.PublicModulus) &&
			bytes.Equal(k1.RsaKey.PublicExponent, k2.RsaKey.PublicExponent)
	}
	if k1.GetKeyType() == "ecc-384-private" || k1.GetKeyType() == "ecc-384-public" ||
		k1.GetKeyType() == "ecc-256-private" || k1.GetKeyType() == "ecc-256-public" {
		if k1.EccKey == nil || k2.EccKey == nil {
			return false
		}
		if k1.EccKey.BasePoint == nil || k2.EccKey.BasePoint == nil {
			return false
		}
		if k1.EccKey.PublicPoint == nil || k2.EccKey.PublicPoint == nil {
			return false
		}
		if k1.EccKey.CurveName == nil || k2.EccKey.CurveName == nil ||
			*k1.EccKey.CurveName != *k2.EccKey.CurveName {
			return false
		}
		return SamePoint(k1.EccKey.BasePoint, k2.EccKey.BasePoint) &&
			SamePoint(k1.EccKey.PublicPoint, k2.EccKey.PublicPoint)
	}
	return false
}

func SameEntity(e1 *certprotos.EntityMessage, e2 *certprotos.EntityMessage) bool {
	if e1.GetEntityType() != e2.GetEntityType() {
		return false
	}
	if e1.GetEntityType() == "measurement" {
		return SameMeasurement(e1.GetMeasurement(), e2.GetMeasurement())
	}
	if e1.GetEntityType() == "key" {
		return SameKey(e1.GetKey(), e2.GetKey())
	}
	if e1.GetEntityType() == "platform" {
		return SamePlatform(e1.GetPlatformEnt(), e2.GetPlatformEnt())
	}
	if e1.GetEntityType() == "environment" {
		return SameEnvironment(e1.GetEnvironmentEnt(), e2.GetEnvironmentEnt())
	}
	return false
}

func SameVseClause(c1 *certprotos.VseClause, c2 *certprotos.VseClause) bool {
	if c1.Subject == nil || c2.Subject == nil {
		return false
	}
	if !SameEntity(c1.GetSubject(), c2.GetSubject()) {
		return false
	}
	if c1.GetVerb() != c2.GetVerb() {
		return false
	}
	if (c1.Object == nil && c2.Object != nil) ||
		(c1.Object != nil && c2.Object == nil) {
		return false
	}
	if c1.Object != nil {
		if !SameEntity(c1.GetObject(), c2.GetObject()) {
			return false
		}
	}
	if (c1.GetClause() == nil && c2.GetClause() != nil) ||
		(c1.GetClause() != nil && c2.GetClause() == nil) {
		return false
	}
	if c1.GetClause() != nil {
		return SameVseClause(c1.GetClause(), c2.GetClause())
	}
	return true
}

func MakeKeyEntity(k *certprotos.KeyMessage) *certprotos.EntityMessage {
	keye := certprotos.EntityMessage{}
	var kn string = "key"
	keye.EntityType = &kn
	keye.Key = k
	return &keye
}

func MakeMeasurementEntity(m []byte) *certprotos.EntityMessage {
	me := certprotos.EntityMessage{}
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
	vseClause.Clause = cl
	return &vseClause
}

func PrintBytes(b []byte) {
	for i := 0; i < len(b); i++ {
		fmt.Printf("%02x", b[i])
	}
	return
}

func PrintEccKey(e *certprotos.EccMessage) {
	fmt.Printf("curve: %s\n", e.GetCurveName())
	if e.CurveP != nil {
		fmt.Printf("P: ")
		PrintBytes(e.CurveP)
		fmt.Printf("\n")
	}
	if e.CurveA != nil {
		fmt.Printf("A: ")
		PrintBytes(e.CurveA)
		fmt.Printf("\n")
	}
	if e.CurveB != nil {
		fmt.Printf("B: ")
		PrintBytes(e.CurveB)
		fmt.Printf("\n")
	}
	if e.BasePoint != nil {
		fmt.Printf("Base: ")
		if e.BasePoint.X != nil && e.BasePoint.Y != nil {
			fmt.Printf("(")
			PrintBytes(e.BasePoint.X)
			fmt.Printf(",\n")
			PrintBytes(e.BasePoint.Y)
			fmt.Printf(")\n")
		}
	}
	if e.PublicPoint != nil {
		fmt.Printf("Public Point: ")
		if e.PublicPoint.X != nil && e.PublicPoint.Y != nil {
			fmt.Printf("(")
			PrintBytes(e.PublicPoint.X)
			fmt.Printf(",\n")
			PrintBytes(e.PublicPoint.Y)
			fmt.Printf(")\n")
		}
	}
	if e.OrderOfBasePoint != nil {
		fmt.Printf("Order of Base Point: ")
		PrintBytes(e.OrderOfBasePoint)
		fmt.Printf("\n")
	}
	if e.PrivateMultiplier != nil {
		fmt.Printf("PrivateMultiplier: ")
		PrintBytes(e.PrivateMultiplier)
		fmt.Printf("\n")
	}
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
	if k.GetKeyName() != "" {
		fmt.Printf("Key name  : %s\n", k.GetKeyName())
	}
	if k.GetKeyType() != "" {
		fmt.Printf("Key type  : %s\n", k.GetKeyType())
	}
	if k.GetKeyFormat() != "" {
		fmt.Printf("Key format: %s\n", k.GetKeyFormat())
	}

	if k.GetKeyType() == "rsa-1024-public" || k.GetKeyType() == "rsa-2048-public" ||
		k.GetKeyType() == "rsa-3072-public" || k.GetKeyType() == "rsa-4096-public" ||
		k.GetKeyType() == "rsa-1024-private" || k.GetKeyType() == "rsa-3072-private" ||
		k.GetKeyType() == "rsa-2048-private" || k.GetKeyType() == "rsa-4096-private" {
		if k.GetRsaKey() != nil {
			PrintRsaKey(k.GetRsaKey())
		}
	} else if k.GetKeyType() == "ecc-384-public" || k.GetKeyType() == "ecc-384-private" ||
		k.GetKeyType() == "ecc-256-public" || k.GetKeyType() == "ecc-256-private" {
		if k.EccKey != nil {
			PrintEccKey(k.EccKey)
		}
	} else if k.GetKeyType() == "aes-256-cbc-hmac-sha256" {
		fmt.Printf("Bits: ")
		PrintBytes(k.SecretKeyBits)
		fmt.Printf("\n")
	} else {
		fmt.Printf("Unknown key type\n")
	}
	return
}

func PrintKeyDescriptor(k *certprotos.KeyMessage) {
	if k.GetKeyType() == "" {
		return
	}

	if k.GetKeyType() == "rsa-2048-private" || k.GetKeyType() == "rsa-2048-public" ||
		k.GetKeyType() == "rsa-4096-private" || k.GetKeyType() == "rsa-4096-public" ||
		k.GetKeyType() == "rsa-3072-private" || k.GetKeyType() == "rsa-3072-public" ||
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
	if k.GetKeyType() == "ecc-384-private" || k.GetKeyType() == "ecc-384-public" ||
		k.GetKeyType() == "ecc-256-private" || k.GetKeyType() == "ecc-256-public" {
		if k.GetEccKey() == nil {
			fmt.Printf("Key[ecc] Bad key")
			return
		}
		fmt.Printf("Key[ecc-%s, ", k.GetEccKey().GetCurveName())
		if k.GetKeyName() != "" {
			fmt.Printf("%s, ", k.GetKeyName())
		}
		if k.GetEccKey().PublicPoint != nil && k.GetEccKey().PublicPoint.X != nil {
			PrintBytes(k.GetEccKey().PublicPoint.X)
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
	if e.GetEntityType() == "environment" {
		PrintEnvironmentDescriptor(e.GetEnvironmentEnt())
	}
	if e.GetEntityType() == "platform" {
		PrintPlatformDescriptor(e.GetPlatformEnt())
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
	if sr.Time != nil {
		fmt.Printf("Time signed : %s\n", *sr.Time)
	}
	if sr.EnclaveKey != nil {
		fmt.Printf("Enclave key:\n")
		PrintKey(sr.EnclaveKey)
	} else {
		fmt.Printf("No enclave key\n")
	}
	if sr.PolicyKey != nil {
		fmt.Printf("Policy key:\n")
		PrintKey(sr.PolicyKey)
	} else {
		fmt.Printf("No policy key\n")
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
	if info.NotBefore != nil && info.NotAfter != nil {
		fmt.Printf("Valid between: %s and %s\n", *info.NotBefore, *info.NotAfter)
	}
	if info.UserData != nil {
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
		fmt.Printf("\n")
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
	if e.GetEntityType() == "environment" {
		PrintEnvironment(e.EnvironmentEnt)
	}
	if e.GetEntityType() == "platform" {
		PrintPlatform(e.PlatformEnt)
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
	sm := certprotos.SignedClaimMessage{}
	if k.GetKeyType() == "rsa-1024-private" {
		var ss string = "rsa-1024-sha256-pkcs-sign"
		sm.SigningAlgorithm = &ss
	} else if k.GetKeyType() == "rsa-2048-private" {
		var ss string = "rsa-2048-sha256-pkcs-sign"
		sm.SigningAlgorithm = &ss
	} else if k.GetKeyType() == "rsa-4096-private" {
		var ss string = "rsa-4096-sha384-pkcs-sign"
		sm.SigningAlgorithm = &ss
	} else if k.GetKeyType() == "rsa-3072-private" {
		var ss string = "rsa-3072-sha384-pkcs-sign"
		sm.SigningAlgorithm = &ss
	} else {
		return nil
	}

	psk := InternalPublicFromPrivateKey(k)
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

func SameProperty(p1 *certprotos.Property, p2 *certprotos.Property) bool {
	if p1 == nil || p2 == nil {
		return false
	}
	if p1.PropertyName == nil || p2.PropertyName == nil {
		return false
	}
	if *p1.PropertyName != *p2.PropertyName {
		return false
	}
	return true
}

func SatisfyingProperty(p1 *certprotos.Property, p2 *certprotos.Property) bool {
	if p1 == nil || p2 == nil || p1.PropertyName == nil || p2.PropertyName == nil {
		return false
	}

	if p1.ValueType == nil || p2.ValueType == nil {
		return false
	}
	if *p1.ValueType != *p2.ValueType {
		return false
	}

	if *p1.ValueType == "string" {
		if p1.StringValue == nil || p2.StringValue == nil {
			return false
		}
		if *p1.StringValue != *p2.StringValue {
			return false
		}
	}
	if *p1.ValueType == "int" {
		if p1.Comparator == nil || p2.Comparator == nil {
			return false
		}
		if *p1.Comparator == ">=" && *p2.Comparator == "=" {
			return *p2.IntValue >= *p1.IntValue
		} else if *p1.Comparator == "=" && *p2.Comparator == "=" {
			return *p1.IntValue == *p2.IntValue
		} else {
			return false
		}
	}
	return true
}

func FindProperty(propName string, p []*certprotos.Property) *certprotos.Property {
	for i := 0; i < len(p); i++ {
		if p[i].PropertyName == nil {
			return nil
		}
		if *p[i].PropertyName == propName {
			return p[i]
		}
	}
	return nil
}

func SatisfyingProperties(p1 *certprotos.Properties, p2 *certprotos.Properties) bool {
	if p1 == nil || p2 == nil {
		return false
	}
	if p1.Props == nil || p2.Props == nil {
		return false
	}
	for i := 0; i < len(p1.Props); i++ {
		if p1.Props[i].PropertyName == nil {
			return false
		}
		pp := FindProperty(*p1.Props[i].PropertyName, p2.Props)
		// If property is not on rule, ignore it.  NEW
		if pp == nil {
			continue
		}
		if !SatisfyingProperty(p1.Props[i], pp) {
			return false
		}
	}
	return true
}

func SameProperties(p1 *certprotos.Properties, p2 *certprotos.Properties) bool {
	if p1 == nil || p2 == nil {
		return false
	}
	if p1.Props == nil || p2.Props == nil {
		return false
	}
	for i := 0; i < len(p1.Props); i++ {
		if p1.Props[i].PropertyName == nil {
			return false
		}
		pp := FindProperty(*p1.Props[i].PropertyName, p2.Props)
		if pp == nil {
			return false
		}
		if !SameProperty(p1.Props[i], pp) {
			return false
		}
	}
	return true
}

func SameEnvironment(p1 *certprotos.Environment, p2 *certprotos.Environment) bool {
	if p1 == nil || p2 == nil {
		return false
	}
	if p1.TheMeasurement == nil || p2.TheMeasurement == nil {
		return false
	}
	if !bytes.Equal(p1.TheMeasurement, p2.TheMeasurement) {
		return false
	}
	if p1.ThePlatform == nil || p2.ThePlatform == nil {
		return false
	}
	return SamePlatform(p1.ThePlatform, p2.ThePlatform)
}

func SamePlatform(p1 *certprotos.Platform, p2 *certprotos.Platform) bool {
	if p1.PlatformType == nil || p2.PlatformType == nil {
		return false
	}
	if p1.HasKey == nil || p2.HasKey == nil {
		return false
	}
	if *p1.HasKey != *p2.HasKey {
		return false
	}
	if *p1.HasKey {
		if p1.AttestKey == nil || p2.AttestKey == nil {
			return false
		}
		if !SameKey(p1.AttestKey, p2.AttestKey) {
			return false
		}
	}
	return SameProperties(p1.Props, p2.Props)
}

func PrintEnvironment(e *certprotos.Environment) {
	if e == nil {
		return
	}
	fmt.Printf("Environment:\n")
	if e.ThePlatform != nil {
		PrintPlatform(e.ThePlatform)
	}
	if e.TheMeasurement != nil {
		fmt.Printf("Measurement: ")
		PrintBytes(e.TheMeasurement)
	}
}

func PrintPlatform(p *certprotos.Platform) {
	if p == nil {
		return
	}
	if p.PlatformType == nil {
		return
	}
	fmt.Printf("Platform:\n")
	fmt.Printf("    Type: %s\n", *p.PlatformType)
	if p.HasKey != nil && *p.HasKey {
		fmt.Printf("    HasKey\n")
	} else {
		fmt.Printf("    NoKey\n")
	}
	if p.AttestKey != nil {
		fmt.Printf("   Key: \n")
		PrintKey(p.AttestKey)
	}
	if p.Props != nil {
		fmt.Printf("    Properties:\n")
		PrintProperties(p.Props)
	}
}

func PrintProperty(p *certprotos.Property) {
	if p == nil || p.PropertyName == nil {
		return
	}
	fmt.Printf("        %s: ", *p.PropertyName)
	if p.ValueType == nil {
		return
	}
	if *p.ValueType == "string" {
		if p.StringValue == nil {
			return
		}
		fmt.Printf("%s\n", *p.StringValue)
	}
	if *p.ValueType == "int" {
		if p.IntValue == nil || p.Comparator == nil {
			return
		}
		fmt.Printf("%s %d\n", *p.Comparator, *p.IntValue)
	}
}

func PrintProperties(p *certprotos.Properties) {
	if p == nil {
		return
	}
	for i := 0; i < len(p.Props); i++ {
		PrintProperty(p.Props[i])
	}
}

func PrintEnvironmentDescriptor(e *certprotos.Environment) {
	if e == nil {
		return
	}
	fmt.Printf("Environment[")
	PrintPlatformDescriptor(e.ThePlatform)
	fmt.Printf(", Measurement: ")
	PrintBytes(e.TheMeasurement)
	fmt.Printf("]")
}

func PrintPlatformDescriptor(p *certprotos.Platform) {
	if p == nil || p.PlatformType == nil {
		return
	}
	fmt.Printf("Platform[%s, ", *p.PlatformType)
	if p.HasKey != nil && *p.HasKey && p.AttestKey != nil {
		PrintKeyDescriptor(p.AttestKey)
		fmt.Printf(", ")
	}
	if p.Props != nil {
		for i := 0; i < len(p.Props.Props); i++ {
			if i != 0 {
				fmt.Printf(", ")
			}
			PrintPropertyDescriptor(p.Props.Props[i])
		}
	}
	fmt.Printf("]")
}

func PrintPropertyDescriptor(p *certprotos.Property) {
	if p == nil || p.PropertyName == nil {
		return
	}
	fmt.Printf("%s: ", *p.PropertyName)
	if p.ValueType == nil {
		return
	}
	if *p.ValueType == "string" {
		if p.StringValue != nil {
			fmt.Printf("%s", *p.StringValue)
		}
	}
	if *p.ValueType == "int" {
		if p.Comparator != nil {
			fmt.Printf("%s", *p.Comparator)
		}
		if p.IntValue != nil {
			fmt.Printf("%d", *p.IntValue)
		}
	}
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

	// Support
	PrintEvidencePackage(req.Support, true)
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
	claimMsg := certprotos.ClaimMessage{}
	err := proto.Unmarshal(sc.SerializedClaimMessage, &claimMsg)
	if err != nil {
		return nil
	}
	vseClause := certprotos.VseClause{}
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

func SizedSocketRead(conn net.Conn) []byte {
	bsize := make([]byte, 4)
	n, err := conn.Read(bsize)
	if err != nil {
		fmt.Printf("SizedSocketRead, error: %d\n", n)
		return nil
	}
	size := int(bsize[0]) + 256*int(bsize[1]) + 256*256*int(bsize[2])
	b := make([]byte, size)
	total := 0
	for total < size {
		n, err = conn.Read(b[total:])
		if err != nil {
			fmt.Printf("SizedSocketRead, error: %d\n", n)
			return nil
		}
		total = total + n
	}
	return b
}

func SizedSocketWrite(conn net.Conn, b []byte) bool {
	size := len(b)
	bs := make([]byte, 4)
	bs[0] = byte(size & 0xff)
	bs[1] = byte((size >> 8) & 0xff)
	bs[2] = byte((size >> 16) & 0xff)
	bs[3] = 0
	_, err := conn.Write(bs)
	if err != nil {
		fmt.Printf("SizedSocketWrite error(1)\n")
		return false
	}
	_, err = conn.Write(b)
	if err != nil {
		fmt.Print(err)
		fmt.Printf("SizedSocketWrite error(2)\n")
		return false
	}
	return true
}

func MakeProperty(name string, t string, sv *string, c *string, iv *uint64) *certprotos.Property {
	p := &certprotos.Property{
		PropertyName: &name,
		ValueType:    &t,
	}
	if t == "string" {
		p.StringValue = sv
	}
	if t == "int" {
		p.Comparator = c
		p.IntValue = iv
	}
	return p
}

func MakePlatform(t string, k *certprotos.KeyMessage, props *certprotos.Properties) *certprotos.Platform {
	hk := false
	if k != nil {
		hk = true
	}
	plat := &certprotos.Platform{
		PlatformType: &t,
		AttestKey:    k,
		Props:        props,
		HasKey:       &hk,
	}
	return plat
}

func MakePlatformEntity(pl *certprotos.Platform) *certprotos.EntityMessage {
	plEnt := "platform"
	pe := &certprotos.EntityMessage{
		EntityType:  &plEnt,
		PlatformEnt: pl,
	}
	return pe
}

func MakeEnvironmentEntity(e *certprotos.Environment) *certprotos.EntityMessage {
	eEnt := "environment"
	ee := &certprotos.EntityMessage{
		EntityType:     &eEnt,
		EnvironmentEnt: e,
	}
	return ee
}

func MakeEnvironment(pl *certprotos.Platform, measurement []byte) *certprotos.Environment {
	e := &certprotos.Environment{
		ThePlatform:    pl,
		TheMeasurement: measurement,
	}
	return e
}

func VerifySignedClaim(c *certprotos.SignedClaimMessage, k *certprotos.KeyMessage) bool {
	PK := rsa.PublicKey{}
	pK := rsa.PrivateKey{}
	if GetRsaKeysFromInternal(k, &pK, &PK) == false {
		fmt.Printf("VerifySignedClaim: Can't get RSA keys\n")
		return false
	}

	cm := certprotos.ClaimMessage{}
	err := proto.Unmarshal(c.SerializedClaimMessage, &cm)
	if err != nil {
		fmt.Printf("VerifySignedClaim: Can't Unmarshal Claim\n")
		return false
	}

	if cm.GetClaimFormat() != "vse-clause" && cm.GetClaimFormat() != "vse-attestation" {
		fmt.Printf("VerifySignedClaim: Unsupported claim format\n")
		return false
	}

	tn := TimePointNow()
	tb := StringToTimePoint(cm.GetNotBefore())
	ta := StringToTimePoint(cm.GetNotAfter())
	if ta != nil && tb != nil {
		if CompareTimePoints(tb, tn) > 0 || CompareTimePoints(ta, tn) < 0 {
			fmt.Printf("VerifySignedClaim: Time violation\n")
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
		return false
	}
	// extract clause
	cl_str := "vse-clause"

	cm := certprotos.ClaimMessage{}
	err := proto.Unmarshal(scm.GetSerializedClaimMessage(), &cm)
	if err != nil {
		fmt.Printf("VerifySignedAssertion: Can't unmarshal claim\n")
		return false
	}
	if cm.GetClaimFormat() == cl_str {
		err = proto.Unmarshal(cm.GetSerializedClaim(), vseClause)
		if err != nil {
			fmt.Printf("VerifySignedAssertion: Can't unmarshal vse claim\n")
			return false
		}
	} else {
		fmt.Printf("VerifySignedAssertion: Must be Vse clause\n")
		return false
	}
	return true
}

func PrintProvedStatements(ps *certprotos.ProvedStatements) {
	for i := 0; i < len(ps.Proved); i++ {
		fmt.Printf("\n%02d ", i)
		v := ps.Proved[i]
		PrintVseClause(v)
		fmt.Printf("\n")
	}
}

func Asn1ToX509(in []byte) *x509.Certificate {
	cert, err := x509.ParseCertificate(in)
	if err != nil {
		return nil
	}
	return cert
}

func X509ToAsn1(cert *x509.Certificate) []byte {
	out, err := asn1.Marshal(cert)
	if err != nil {
		fmt.Printf("X509ToAsn1 error: %s\n", err.Error())
		return nil
	}
	return out
}

func CheckTimeRange(nb *string, na *string) bool {
	if nb == nil || na == nil {
		return false
	}
	tn := TimePointNow()
	tb := StringToTimePoint(*nb)
	ta := StringToTimePoint(*na)
	if tn == nil || ta == nil && tb == nil {
		return false
	}
	if CompareTimePoints(tb, tn) > 0 || CompareTimePoints(ta, tn) < 0 {
		fmt.Printf("CheckTimeRange out of range\n")
		return false
	}
	return true
}

func LittleToBigEndian(in []byte) []byte {
	out := make([]byte, len(in))
	for i := 0; i < len(in); i++ {
		out[len(in)-1-i] = in[i]
	}
	return out
}

func ProduceAdmissionCert(remoteIP string, issuerKey *certprotos.KeyMessage, issuerCert *x509.Certificate,
	subjKey *certprotos.KeyMessage, subjName string, subjOrg string,
	serialNumber uint64, durationSeconds float64) *x509.Certificate {

	dur := int64(durationSeconds * 1000 * 1000 * 1000)
	cert := x509.Certificate{
		SerialNumber: big.NewInt(int64(serialNumber)),
		Subject: pkix.Name{
			CommonName:   subjName,
			Organization: []string{subjOrg},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(dur)),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	if remoteIP != "" {
		cert.IPAddresses = []net.IP{net.ParseIP(remoteIP)}
	}
	spK := rsa.PrivateKey{}
	sPK := rsa.PublicKey{}
	if !GetRsaKeysFromInternal(subjKey, &spK, &sPK) {
		fmt.Printf("ProduceAdmissionCert: Can't get Rsa subject key\n")
		return nil
	}

	ipK := rsa.PrivateKey{}
	iPK := rsa.PublicKey{}
	if !GetRsaKeysFromInternal(issuerKey, &ipK, &iPK) {
		fmt.Printf("ProduceAdmissionCert: Can't get Rsa issuer keys\n")
		return nil
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &cert, issuerCert, &sPK, crypto.Signer(&ipK))
	if err != nil {
		fmt.Printf("ProduceAdmissionCert: Can't Create Certificate\n")
		return nil
	}
	newCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		fmt.Printf("ProduceAdmissionCert: Can't Parse Certificate\n")
		return nil
	}
	return newCert
}

func GetIssuerNameFromCert(cert *x509.Certificate) string {
	return cert.Issuer.CommonName
}

func GetSubjectNameFromCert(cert *x509.Certificate) *string {
	return &cert.Subject.CommonName
}

func GetVcekExtValue(ext pkix.Extension) (uint8, error) {
	if ext.Value[0] != 0x2 {
		fmt.Printf("Invalid extension type!\n")
		return 0, errors.New("Invalid extension type")
	}
	if ext.Value[1] != 0x1 && ext.Value[1] != 0x2 {
		fmt.Printf("Invalid extension length!\n")
		return 0, errors.New("Invalid extension length")
	}
	return ext.Value[ext.Value[1]+1], nil
}

func GetSubjectKey(cert *x509.Certificate) *certprotos.KeyMessage {
	name := GetSubjectNameFromCert(cert)
	if name == nil {
		return nil
	}

	PKrsa, ok := cert.PublicKey.(*rsa.PublicKey)
	if ok {
		k := certprotos.KeyMessage{}
		if !GetInternalKeyFromRsaPublicKey(*name, PKrsa, &k) {
			fmt.Printf("GetSubjectKey: Can't internal rsa public key\n")
			return nil
		}
		return &k
	}
	PKecc, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if ok {
		k := certprotos.KeyMessage{}
		if !GetInternalKeyFromEccPublicKey(*name, PKecc, &k) {
			fmt.Printf("GetSubjectKey: Can't internal ecc public key\n")
			return nil
		}

		// Look for AMD VCEK cert extensions if they exist
		oidBlSPL := "1.3.6.1.4.1.3704.1.3.1"
		oidTeeSPL := "1.3.6.1.4.1.3704.1.3.2"
		oidSnpSPL := "1.3.6.1.4.1.3704.1.3.3"
		oidUcodeSPL := "1.3.6.1.4.1.3704.1.3.8"
		oidHwID := "1.3.6.1.4.1.3704.1.4"
		const hwIDLen = 64
		snpExtExist := false
		var blSPL, teeSPL, snpSPL, ucodeSPL uint8
		for _, ext := range cert.Extensions {
			var err error
			if strings.Contains(ext.Id.String(), oidBlSPL) {
				blSPL, err = GetVcekExtValue(ext)
				if err == nil {
					snpExtExist = true
				} else {
					snpExtExist = false
					break
				}
			} else if strings.Contains(ext.Id.String(), oidTeeSPL) {
				teeSPL, err = GetVcekExtValue(ext)
				if err == nil {
					snpExtExist = true
				} else {
					snpExtExist = false
					break
				}
			} else if strings.Contains(ext.Id.String(), oidSnpSPL) {
				snpSPL, err = GetVcekExtValue(ext)
				if err == nil {
					snpExtExist = true
				} else {
					snpExtExist = false
					break
				}
			} else if strings.Contains(ext.Id.String(), oidUcodeSPL) {
				ucodeSPL, err = GetVcekExtValue(ext)
				if err == nil {
					snpExtExist = true
				} else {
					snpExtExist = false
					break
				}
			} else if strings.Contains(ext.Id.String(), oidHwID) {
				if hwIDLen != len(ext.Value) {
					fmt.Printf("Wrong HwID length: %d\n", len(ext.Value))
					snpExtExist = false
					k.SnpChipid = make([]byte, 0, hwIDLen)
					break
				} else {
					snpExtExist = true
					k.SnpChipid = ext.Value
				}
			}
		}
		var tcbVer uint64
		if snpExtExist {
			tcbVer = uint64(blSPL) | uint64(teeSPL)<<8 | uint64(snpSPL)<<48 | uint64(ucodeSPL)<<56
			fmt.Printf("AMD VCEK extensions exist. TCB_VERSION: %08x\n", tcbVer)
		} else {
			tcbVer = ^uint64(0)
		}
		k.SnpTcbVersion = &tcbVer

		return &k
	}

	return nil
}

func GetIssuerKey(cert *x509.Certificate) *certprotos.KeyMessage {
	return nil
}

func VerifyAdmissionCert(policyCert *x509.Certificate, cert *x509.Certificate) bool {
	certPool := x509.NewCertPool()
	certPool.AddCert(policyCert)
	opts := x509.VerifyOptions{
		Roots: certPool,
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
		err := proto.Unmarshal(ev.SerializedEvidence, &sc)
		if err != nil {
			return
		}
		PrintSignedClaim(&sc)
		fmt.Printf("\n")
	} else if ev.GetEvidenceType() == "signed-vse-attestation-report" {
		sr := certprotos.SignedReport{}
		err := proto.Unmarshal(ev.SerializedEvidence, &sr)
		if err != nil {
			return
		}
		PrintSignedReport(&sr)
		fmt.Printf("\n")
	} else if ev.GetEvidenceType() == "oe-attestation-report" {
		PrintBytes(ev.SerializedEvidence)
		fmt.Printf("\n")
	} else if ev.GetEvidenceType() == "sev-attestation" {
		PrintBytes(ev.SerializedEvidence)
	} else if ev.GetEvidenceType() == "gramine-attestation" {
		PrintBytes(ev.SerializedEvidence)
	} else if ev.GetEvidenceType() == "cert" {
		cx509 := Asn1ToX509(ev.SerializedEvidence)
		fmt.Printf("Issuer: %s, Subject: %s\n", GetIssuerNameFromCert(cx509), *GetSubjectNameFromCert(cx509))
		PrintBytes(ev.SerializedEvidence)
		fmt.Printf("\n")
	} else {
		return
	}
}

func PrintEvidencePackage(evp *certprotos.EvidencePackage, printAll bool) {
	fmt.Printf("\nProver type: %s\n", evp.GetProverType())
	for i := 0; i < len(evp.FactAssertion); i++ {
		ev := evp.FactAssertion[i]
		if printAll {
			PrintEvidence(ev)
			fmt.Printf("\n\n")
		} else {
			fmt.Printf("    Evidence type: %s\n", ev.GetEvidenceType())
		}
	}
}

type CertKeysSeen struct {
	name string
	pk   certprotos.KeyMessage
}

type CertSeenList struct {
	maxSize  int
	size     int
	keysSeen [30]CertKeysSeen
}

func AddKeySeen(list *CertSeenList, k *certprotos.KeyMessage) bool {
	if (list.maxSize - 1) <= list.size {
		return false
	}
	entry := &list.keysSeen[list.size]
	list.size = list.size + 1
	entry.name = k.GetKeyName()
	entry.pk = *k
	return true
}

func FindKeySeen(list *CertSeenList, name string) *certprotos.KeyMessage {
	for j := 0; j < list.size; j++ {
		if list.keysSeen[j].name == name {
			return &list.keysSeen[j].pk
		}
	}
	return nil
}

func StripPemHeaderAndTrailer(pem string) *string {
	sl := strings.Split(pem, "\n")
	if len(sl) < 3 {
		return nil
	}
	s := strings.Join(sl[1:len(sl)-2], "\n")
	return &s
}

func KeyFromPemFormat(pem string) *certprotos.KeyMessage {
	// base64 decode pem
	der, err := b64.StdEncoding.DecodeString(pem)
	if err != nil || der == nil {
		fmt.Printf("KeyFromPemFormat: base64 decode error\n")
		return nil
	}
	cert := Asn1ToX509(der)
	if cert == nil {
		fmt.Printf("KeyFromPemFormat: Can't convert cert\n")
		return nil
	}

	return GetSubjectKey(cert)
}

func PrintX509Cert(cert *x509.Certificate) {
	fmt.Printf("Certificate %d\n", cert.SerialNumber)
	fmt.Printf("\tSubject: %+v\n", cert.Subject)
	fmt.Printf("\tIssuer: %+v\n", cert.Issuer)
	if cert.IsCA {
		fmt.Printf("\tRoot cert\n")
	} else {
	}
	fmt.Printf("\tSubordinate cert\n")
	fmt.Printf("\tDNS Names: %+v\n", cert.DNSNames)
	fmt.Printf("\tEmailAddresses: %+v\n", cert.EmailAddresses)
	fmt.Printf("\tIPAddresses: %+v\n", cert.IPAddresses)
	fmt.Printf("\tKeyUsage: %+v\n", cert.KeyUsage)
	fmt.Printf("\tNot before: %+v\n", cert.NotBefore)
	fmt.Printf("\tNot after : %+v\n", cert.NotAfter)
	fmt.Printf("\tSignature Alg: %+v\n", cert.SignatureAlgorithm)
}

//  --------------------------------------------------------------------

//  Simulated enclave
//  --------------------------------------------------------------------

var privateAttestKey *certprotos.KeyMessage = nil
var publicAttestKey *certprotos.KeyMessage = nil
var rsaPublicAttestKey rsa.PublicKey
var rsaPrivateAttestKey rsa.PrivateKey
var sealingKey [64]byte
var sealIv [16]byte
var simulatedInitialized bool = false

func InitSimulatedEnclave() bool {
	privateAttestKey = MakeVseRsaKey(2048)
	var tk string = "simulatedAttestKey"
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
	tf := TimePointPlus(tn, 365*86400)
	nb := TimePointToString(tn)
	na := TimePointToString(tf)
	cl1 := MakeClaim(toSay, "vse-attestation", "attestation", nb, na)
	serCl, err := proto.Marshal(cl1)
	if err != nil {
		return nil
	}
	sc := certprotos.SignedClaimMessage{}
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

func BytesToUint64(b []byte) uint64 {
	t := uint64(b[0])
	t = (t << 8) | uint64(b[1])
	t = (t << 8) | uint64(b[2])
	t = (t << 8) | uint64(b[3])
	t = (t << 8) | uint64(b[4])
	t = (t << 8) | uint64(b[5])
	t = (t << 8) | uint64(b[6])
	t = (t << 8) | uint64(b[7])
	return t
}
