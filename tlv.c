#include "tlv.h"
#include <stdint.h>


// Debugging
#ifndef DEBUG
    #define TLV_PRINTF(...)
    #define TLV_LOG_HEX(...)
#else
    #include "tlv_debug.h"
#endif
#define TLV_LOG(...) TLV_PRINTF("<tlv debug> " __VA_ARGS__)
#define TLV_LOG_LINE() TLV_PRINTF("\n\r")

#define GET_MSBYTE(i) ((i >> 24) & 0xFF)


// Compute the minimum number of bytes required to represent a number
static inline uint8_t min_size(uint32_t d)
{
    uint8_t n = 0;
    while (d) {
        d >>= 8;
        n++;
    }
    return n;
}

// Left-shift a number, until it has no leading zeros
static inline uint32_t trim_leading_zeros(uint32_t i)
{
    while (i <= 0x00FFFFFF)
        i <<= 8;
    return i;
}

// Read the tag field from the source buffer and decode it
// Modifies src to point to next byte after tag bytes
// Returns tag, or negative error
static inline int decode_tag(uint32_t* tag, const uint8_t** src, int srcLen)
{
    if (!tag || !src || !*src)
        return TLV_ERR_BADARG;
    if (srcLen <= 0)
        return TLV_ERR_NODATA;

    const uint8_t* s = *src;
    const uint8_t* const BEGIN = s;
    const uint8_t* const END = s + srcLen;
    *src = 0; // Reset src to null

    if ((*s & 0x1F) > 30) { // Is the tag extended?
        // First subsequent octet must not be 0
        if (srcLen < 2 || *(s+1) == 0)
            return TLV_ERR_INVAL;

        *tag = *s++;
        do {
            // Detect overflow
            if ((*tag << 8) < *tag)
                return TLV_ERR_OVERFLOW;

            // Join each octet of the tag
            *tag = (*tag << 8) + (*s & 0xFF);
        } while (s < END && *s++ & 0x80); // Last octet will clear MSB

        if (s > END)
            return TLV_ERR_MSGSIZE;

        *src = s;
    } else { // Tag is just one byte
        *src = s+1;
        *tag = *s;
    }

    return s-BEGIN;
}

// Encode the tag and Write it to the destination buffer
// Modifies dest to point to next byte after tag bytes
// Returns number of bytes written, or negative error
static inline int encode_tag(uint8_t** dest, int destLen, uint32_t tag)
{
    if (!dest || !*dest)
        return TLV_ERR_BADARG;
    if (destLen <= 0)
        return TLV_ERR_NOMEM;

    uint8_t* d = *dest;
    const uint8_t* const BEGIN = d;
    const uint8_t* const END = d + destLen;
    *dest = 0; // Reset dest to null

    if (tag < 0 || tag > 0xFF) { // Extended tag
        // Scan to first tag byte
        tag = trim_leading_zeros(tag);
        
        // Check first byte is valid extended byte
        if ((GET_MSBYTE(tag) & 0x1F) < 31)
            return TLV_ERR_INVAL;

        // Write tag bytes
        while (tag > 0x00FFFFFF) {
            // Check for enough memory
            if (d >= END)
                return TLV_ERR_NOMEM;

            // Copy next tag byte
            *d++ = GET_MSBYTE(tag);
            tag <<= 8;
        }
    } else { // Short tag
        if ((tag & 0x1F) > 30)
            return TLV_ERR_INVAL; // Invalid short tag

        // Check for end of buffer
        if (d >= END)
            return TLV_ERR_NOMEM;

        // Write tag byte
        *d++ = tag & 0xFF;
    }

    *dest = d;
    return d-BEGIN; 
}

// Read the length field from the source buffer and decode it
// Modifies src to point to next byte after length bytes
// Returns number of bytes read or negative error
static inline int decode_length(uint32_t* length, const uint8_t** src, int srcLen)
{
    if (!length || !src || !*src)
        return TLV_ERR_BADARG;
    if (srcLen <= 0)
        return TLV_ERR_NODATA;

    const uint8_t* s = *src;
    const uint8_t* const BEGIN = s;
    const uint8_t* const END = s + srcLen;
    *src = (void*) 0; // Reset src to null

    if (*s & 0x80) { // Is the length in long form?
        // The first byte must not be 0xFF
        if (*s == 0xFF)
            return TLV_ERR_INVAL;

        const int N = *s++ & 0x7F; // Number of length bytes to use
        if (N > 4 || (N > 3 && s[3] & 0x80))
            return TLV_ERR_OVERFLOW;

        int len = 0;
        for(int i = 0; i < N; i++)
            len = (len << 8) + s[i];
        *src = s+N;
        *length = len;
    } else { // Tag is just one byte
        *src = s+1;
        *length = *s;
    }

    if (s >= END)
        return TLV_ERR_MSGSIZE;

    return s-BEGIN;
}

// Encode the length and Write it to the destination buffer
// Modifies dest to point to next byte after length bytes
// Returns number of bytes written, or negative error
static inline int encode_length(uint8_t** dest, int destLen, uint32_t length)
{
    if (!dest || !*dest || length <= 0)
        return TLV_ERR_BADARG;
    if (destLen <= 0)
        return TLV_ERR_NOMEM;

    uint8_t* d = *dest;
    const uint8_t* const BEGIN = d;
    const uint8_t* const END = d + destLen;
    *dest = 0; // Reset dest to null

    if (length > 0x7F) { // Long form
        // Determine how many length bytes
        int n = min_size(length);
        if (n > 0x7E) // This long cannot fit in TLV encoding
            return TLV_ERR_OVERFLOW;
        if (d >= END)
            return TLV_ERR_NOMEM;
        *d++ = (n | 0x80) & 0xFF; 

        // Write length bytes
        length = trim_leading_zeros(length);
        while (n-- > 0) {
            if (d >= END)
                return TLV_ERR_NOMEM;

            *d++ = GET_MSBYTE(length);
            length <<= 8;
        }
    } else { // Short form
        if (d >= END)
            return TLV_ERR_NOMEM;
        *d++ = length & 0xFF;
    }

    *dest = d;
    return d-BEGIN;
}

int tlv_parse(TLVToken* t, int* nTok, const void* src, int srcLen)
{
    if (!t || !nTok || *nTok < 0 || !src || srcLen < 0)
        return TLV_ERR_BADARG;

    const uint8_t* s = src;
    const uint8_t* const BEGIN = s;
    const uint8_t* const END = s + srcLen;

    TLV_LOG("Parse input: ");
    TLV_LOG_HEX(src, srcLen);
    TLV_LOG_LINE();

    int n = 0;
    int err = 0;
    while (s <= END) {
        // Check for memory
        if (n >= *nTok) {
            n = TLV_ERR_NOMEM;
            break;
        }

        // Decode the tag field
        err = decode_tag(&t[n].tag, &s, END-s);
        if (err < 0) {
            n = err;
            break;
        }
        TLV_LOG("tag: %08X\n\r", t[n].tag);

        // Decode the length field
        err = decode_length(t[n].len, &s, END-s);
        if (err < 0) {
            n = err;
            break;
        }
        TLV_LOG("len: %u\n\r", t[n].len);

        // Save pointer to value field
        t[n].val = s;
        if (t[n].val == 0) {
            n = TLV_ERR_UNKNOWN;
            break;
        }
        TLV_LOG("val: ");
        TLV_LOG_HEX(t[n].val, t[n].len);
        TLV_LOG_LINE();

        // Point to next object
        s = t[n].val;
        n++;
    }

    // Output the number of tokens found
    if (n >= 0)
        *nTok = n;

    // Handle errors
    if (n < 0) // Error during parse loop
        return n;
    if (s > END) // TLV data exceeds byte array provided
        return TLV_ERR_MSGSIZE;

    // Return the total length of the TLV data
    return s-BEGIN;
}

int tlv_serialize(void* dest, int* len, const TLVToken* t, int nTok)
{
    if (!dest || !len || *len < 0 || !t || nTok < 0)
        return TLV_ERR_BADARG;

    uint8_t* d = dest;
    const uint8_t* const BEGIN = d;
    const uint8_t* const END = d + *len;

    TLV_LOG("Serializing %d tokens into %i byte buffer\n\r", nTok, *len);

    *len = 0;
    int err = 0;
    for (int i = 0; i <= nTok; i++) {
        // Write the tag field
        TLV_LOG("tag: %08X\n\r", t[i].tag);
        err = encode_tag(&d, END-d, t[i].tag);
        if (err < 0)
            return err;
        if (*len + err < *len)
            return TLV_ERR_OVERFLOW;

        // Write the length field
        TLV_LOG("len: %u\n\r", t[i].len);
        err = encode_length(&d, END-d, t[i].len);
        if (err < 0)
            return err;
        if (*len + err < *len)
            return TLV_ERR_OVERFLOW;

        // Copy the value
        TLV_LOG("val: ");
        TLV_LOG_HEX(t[i].val, t[i].len);
        TLV_LOG_LINE();
        const uint8_t* v = t[i].val;
        const uint8_t* const VAL_END = v + t[i].len;
        while (v < VAL_END) {
            // Make sure not to overrun the buffer
            if (d >= END)
                return TLV_ERR_NOMEM;

            *d++ = *v++;
        }
    }

    // Return total serialized length
    return *len = d-BEGIN;
}

