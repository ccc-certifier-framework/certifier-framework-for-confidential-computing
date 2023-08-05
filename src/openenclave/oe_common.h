#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef _OE_COMMON_H_
#  define _OE_COMMON_H_

#  ifndef byte
typedef unsigned char byte;
#  endif

#  ifdef OE_DEBUG
#    define OE_DEBUG_PRINTF(...) printf(__VA_ARGS__)
#  else
#    define OE_DEBUG_PRINTF(...) ;
#  endif

#endif /* _OE_COMMON_H_ */
