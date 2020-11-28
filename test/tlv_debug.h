#ifndef __TLV_DEBUG_H__
#define __TLV_DEBUG_H__

#include <stdio.h>

extern void print_hex(const void* src, int len);

#define TLV_PRINTF printf
#define TLV_LOG_HEX print_hex

#endif /* __TLV_DEBUG_H__ */
