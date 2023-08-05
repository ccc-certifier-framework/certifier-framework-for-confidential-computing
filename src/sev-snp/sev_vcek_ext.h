//  Copyright (c) 2023, VMware Inc, and the Certifier Authors.  All rights
//  reserved.
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

#ifndef _SEV_VCEK_EXT_H_
#define _SEV_VCEK_EXT_H_

/*
 * OIDs for the custom extensions AMD embedded into the VCEK certificate
 * retrieved from the AMD KDS. Refer to Table 8, Versioned Chip Endorsement
 * Key (VCEK) Certificate and KDS Interface Specification, revision 0.51,
 * Jan 2023, for details.
 */
#define VCEK_EXT_STRUCT_VERSION "1.3.6.1.4.1.3704.1.1"
#define VCEK_EXT_PRODUCT_NAME   "1.3.6.1.4.1.3704.1.2"
#define VCEK_EXT_BLSPL          "1.3.6.1.4.1.3704.1.3.1"
#define VCEK_EXT_TEESPL         "1.3.6.1.4.1.3704.1.3.2"
#define VCEK_EXT_SNPSPL         "1.3.6.1.4.1.3704.1.3.3"
#define VCEK_EXT_SPL4           "1.3.6.1.4.1.3704.1.3.4"
#define VCEK_EXT_SPL5           "1.3.6.1.4.1.3704.1.3.5"
#define VCEK_EXT_SPL6           "1.3.6.1.4.1.3704.1.3.6"
#define VCEK_EXT_SPL7           "1.3.6.1.4.1.3704.1.3.7"
#define VCEK_EXT_UCODESPL       "1.3.6.1.4.1.3704.1.3.8"
#define VCEK_EXT_HWID           "1.3.6.1.4.1.3704.1.4"

#endif /* _SEV_VCEK_EXT_H_ */
