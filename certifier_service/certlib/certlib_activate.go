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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"os"

	certprotos "github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing/certifier_service/certprotos"
	gramineverify "github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing/certifier_service/gramineverify"
	isletverify "github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing/certifier_service/isletverify"
	oeverify "github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing/certifier_service/oeverify"
	tpmverify "github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing/certifier_service/tpmverify"
	"google.golang.org/protobuf/proto"
	*/
)

//      ------------------------------------------------------------------------

var endorsementTrustInitialized bool = false
var endorsementTrustList []byte


func InitEndorsementTrust(fileName string) bool {
  return true
}

//      ------------------------------------------------------------------------

