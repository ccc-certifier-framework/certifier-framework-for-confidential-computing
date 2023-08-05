#ifndef _SEALING_H_
#define _SEALING_H_

#include <stddef.h>
#include "oe_common.h"

#define POLICY_UNIQUE  1
#define POLICY_PRODUCT 2

bool oe_Seal(int   seal_policy,
             int   in_size,
             byte *in,
             int   opt_size,
             byte *opt,
             int * size_out,
             byte *out);
bool oe_Unseal(int   in_size,
               byte *in,
               int   opt_size,
               byte *opt,
               int * size_out,
               byte *out);

#endif /* _SEALING_H_ */
