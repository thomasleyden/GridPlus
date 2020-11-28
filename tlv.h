#ifndef __TLV_H__
#define __TLV_H__

#include <stdint.h>

typedef enum {
    TLV_ERR_UNKNOWN    = -128, // Unknown failure
    TLV_ERR_BADARG,            // Bad argument
    TLV_ERR_OVERFLOW,          // Overflow detected
    TLV_ERR_NOMEM,             // Not enough memory
    TLV_ERR_INVAL,             // Invalid TLV data
    TLV_ERR_MSGSIZE,           // TLV data exceeds provided size
    TLV_ERR_NODATA,            // Not enough data was provided
    TLV_ERR_NOENT,             // No entry was found
    TLV_ERR_OK         = 0,    // No error
} TLVError;

// A token describes a TLV object. Tag field does not need to occupy the
// entire 32b width. For example, a tag of 0x14 will properly be encoded as a
// single byte field.
typedef struct {
    uint32_t    tag;
    uint32_t    len;
    const void* val;
} TLVToken;


/**
 * Parse TLV encoded data for TLV objects
 *
 * This parser will parse only one level of TLV objects. An object may include
 * TLV encoded data itself (ie nested TLV). To parse nested TLV objects, this
 * parser should be invoked again on the object's value data.
 *
 * In the event of an TLV_ERR_NOMEM error, the output of `nTok` will still
 * represent the total number of tokens found in the byte array.
 *
 * [output] t       Array of tokens to be populated with parsed data
 * [in/out] nTok    Input size of the array / Output number of tokens parsed
 * [input]  src     Source pointer to TLV data
 * [input]  srcLen  Length source data to parse
 *
 * Returns number of tokens parsed, or negative error
 */
int tlv_parse(TLVToken* t, int* nTok, const void* src, int srcLen);

/**
 * Serialize an array of TLV objects
 *
 * [output] dest    Destination to receive serialized data
 * [in/out] len     Input size of the destination / Output serialized length
 * [input]  t       Array of tokens to be serialized
 * [input]  nTok    Number of tokens to be serialized
 *
 * Returns the length of the serialized data, or negative error
 */
int tlv_serialize(void* dest, int* len, const TLVToken* t, int nTok);


#endif /* __TLV_H__ */
