#include "tlv.h"
#include <stdint.h>


// Debugging
#define DEBUG 1
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
static inline int decode_tag(uint32_t* pTag, const uint8_t** ppSrc, int srcLen)
{
    if (!pTag || !ppSrc || !*ppSrc)
        return TLV_ERR_BADARG;
    if (srcLen <= 0)
        return TLV_ERR_NODATA;

    const uint8_t* pSrcCurr = *ppSrc;
    const uint8_t* const BEGIN = pSrcCurr;
    const uint8_t* const END = pSrcCurr + srcLen;
    *ppSrc = 0; // Reset src to null

    if ((*pSrcCurr & 0x1F) > 30) { // Is the tag extended?
        // First subsequent octet must not be 0
        if (srcLen < 2 || *(pSrcCurr+1) == 0)
            return TLV_ERR_INVAL;

        *pTag = *pSrcCurr++;
        do {
            // Detect overflow
            if ((*pTag << 8) < *pTag)
                return TLV_ERR_OVERFLOW;

            // Join each octet of the tag
            *pTag = (*pTag << 8) + (*pSrcCurr & 0xFF);
        } while (pSrcCurr < END && *pSrcCurr++ & 0x80); // Last octet will clear MSB

        if (pSrcCurr > END)
            return TLV_ERR_MSGSIZE;

        *ppSrc = pSrcCurr;
    } else { // Tag is just one byte
        *ppSrc = pSrcCurr+1;
        *pTag = *pSrcCurr;
    }

    return pSrcCurr-BEGIN;
}

// Encode the tag and Write it to the destination buffer
// Modifies dest to point to next byte after tag bytes
// Returns number of bytes written, or negative error
static inline int encode_tag(uint8_t** ppDest, int destLen, uint32_t tag)
{
    if (!ppDest || !*ppDest)
        return TLV_ERR_BADARG;
    if (destLen <= 0)
        return TLV_ERR_NOMEM;

    uint8_t* pDestCurr = *ppDest;
    const uint8_t* const BEGIN = pDestCurr;
    const uint8_t* const END = pDestCurr + destLen;
    *ppDest = 0; // Reset dest to null

    if (tag < 0 || tag > 0xFF) { // Extended tag
        // Scan to first tag byte
        tag = trim_leading_zeros(tag);
        
        // Check first byte is valid extended byte
        if ((GET_MSBYTE(tag) & 0x1F) < 31)
            return TLV_ERR_INVAL;

        // Write tag bytes
        while (tag > 0x00FFFFFF) {
            // Check for enough memory
            if (pDestCurr >= END)
                return TLV_ERR_NOMEM;

            // Copy next tag byte
            *pDestCurr++ = GET_MSBYTE(tag);
            tag <<= 8;
        }
    } else { // Short tag
        if ((tag & 0x1F) > 30)
            return TLV_ERR_INVAL; // Invalid short tag

        // Check for end of buffer
        if (pDestCurr >= END)
            return TLV_ERR_NOMEM;

        // Write tag byte
        *pDestCurr++ = tag & 0xFF;
    }

    *ppDest = pDestCurr;
    return pDestCurr-BEGIN; 
}

// Read the length field from the source buffer and decode it
// Modifies src to point to next byte after length bytes
// Returns number of bytes read or negative error
static inline int decode_length(uint32_t* pLength, const uint8_t** ppSrc, int srcLen)
{
    if (!pLength || !ppSrc || !*ppSrc)
        return TLV_ERR_BADARG;
    if (srcLen <= 0)
        return TLV_ERR_NODATA;

    const uint8_t* pSrcCurr = *ppSrc;
    const uint8_t* const BEGIN = pSrcCurr;
    const uint8_t* const END = pSrcCurr + srcLen;
    *ppSrc = (void*) 0; // Reset src to null

    if (*pSrcCurr & 0x80) { // Is the length in long form?
        // The first byte must not be 0xFF
        if (*pSrcCurr == 0xFF)
            return TLV_ERR_INVAL;

        const int N = *pSrcCurr++ & 0x7F; // Number of length bytes to use
        if (N > 4 || (N > 3 && pSrcCurr[3] & 0x80))
            return TLV_ERR_OVERFLOW;

        int len = 0;
        for(int i = 0; i < N; i++)
            len = (len << 8) + pSrcCurr[i];
        *ppSrc = pSrcCurr+N;
        *pLength = len;
    } else { // Tag is just one byte
        *ppSrc = pSrcCurr+1;
        *pLength = *pSrcCurr;
    }

    if (pSrcCurr >= END)
        return TLV_ERR_MSGSIZE;

    return pSrcCurr-BEGIN;
}

// Encode the length and Write it to the destination buffer
// Modifies dest to point to next byte after length bytes
// Returns number of bytes written, or negative error
static inline int encode_length(uint8_t** ppDest, int destLen, uint32_t length)
{
    if (!ppDest || !*ppDest || length <= 0)
        return TLV_ERR_BADARG;
    if (destLen <= 0)
        return TLV_ERR_NOMEM;

    uint8_t* pDestCurr = *ppDest;
    const uint8_t* const BEGIN = pDestCurr;
    const uint8_t* const END = pDestCurr + destLen;
    *ppDest = 0; // Reset dest to null

    if (length > 0x7F) { // Long form
        // Determine how many length bytes
        int n = min_size(length);
        if (n > 0x7E) // This long cannot fit in TLV encoding
            return TLV_ERR_OVERFLOW;
        if (pDestCurr >= END)
            return TLV_ERR_NOMEM;
        *pDestCurr++ = (n | 0x80) & 0xFF; 

        // Write length bytes
        length = trim_leading_zeros(length);
        while (n-- > 0) {
            if (pDestCurr >= END)
                return TLV_ERR_NOMEM;

            *pDestCurr++ = GET_MSBYTE(length);
            length <<= 8;
        }
    } else { // Short form
        if (pDestCurr >= END)
            return TLV_ERR_NOMEM;
        *pDestCurr++ = length & 0xFF;
    }

    *ppDest = pDestCurr;
    return pDestCurr-BEGIN;
}

int tlv_parse(TLVToken* pTokenList, int* nTok, const void* pSrc, int srcLen)
{
    if (!pTokenList || !nTok || *nTok < 0 || !pSrc || srcLen < 0)
        return TLV_ERR_BADARG;

    const uint8_t* pSrcCurr = pSrc;
    const uint8_t* const BEGIN = pSrcCurr;
    const uint8_t* const END = pSrcCurr + srcLen;

    TLV_LOG("Parse input: ");
    TLV_LOG_HEX(pSrc, srcLen);
    TLV_LOG_LINE();

    int err = 0;
    int currTokenCnt = 0;
    for(currTokenCnt = 0; currTokenCnt < *nTok; currTokenCnt++) {
        // Check for memory
        if (currTokenCnt >= *nTok) {
            currTokenCnt = TLV_ERR_NOMEM;
            break;
        }

        // Decode the tag field
        err = decode_tag(&pTokenList[currTokenCnt].tag, &pSrcCurr, END-pSrcCurr);
        if (err < 0) {
            break;
        }
        TLV_LOG("tag: %08X\n\r", pTokenList[currTokenCnt].tag);

        // Decode the length field
        err = decode_length(&pTokenList[currTokenCnt].len, &pSrcCurr, END-pSrcCurr);
        if (err < 0) {
            break;
        }
        TLV_LOG("len: %u\n\r", pTokenList[currTokenCnt].len);

        // Save pointer to value field
        pTokenList[currTokenCnt].val = pSrcCurr;
        if (pTokenList[currTokenCnt].val == 0) {
            err = TLV_ERR_UNKNOWN;
            break;
        }
        TLV_LOG("val: ");
        TLV_LOG_HEX(pTokenList[currTokenCnt].val, pTokenList[currTokenCnt].len);
        TLV_LOG_LINE();

        // Point to next object
        pSrcCurr = pSrcCurr + pTokenList[currTokenCnt].len;
    }

    // Output the number of tokens found
    if (currTokenCnt >= 0)
        *nTok = currTokenCnt;

    // Handle errors
    if (currTokenCnt < 0) // Error during parse loop
        return err;
    if (pSrcCurr > END) // TLV data exceeds byte array provided
        return TLV_ERR_MSGSIZE;

    // Return the total length of the TLV data
    return pSrcCurr-BEGIN;
}

int tlv_serialize(void* pDest, int* pLen, const TLVToken* pToken, int nTok)
{
    if (!pDest || !pLen || *pLen < 0 || !pToken || nTok < 0)
        return TLV_ERR_BADARG;

    uint8_t* pDestCurr = pDest;
    const uint8_t* const BEGIN = pDestCurr;
    const uint8_t* const END = pDestCurr + *pLen;

    TLV_LOG("Serializing %d tokens into %i byte buffer\n\r", nTok, *pLen);

    *pLen = 0;
    int err = 0;
    for (int currTokenCnt = 0; currTokenCnt < nTok; currTokenCnt++) {
        // Write the tag field
        TLV_LOG("tag: %08X\n\r", pToken[currTokenCnt].tag);
        err = encode_tag(&pDestCurr, END-pDestCurr, pToken[currTokenCnt].tag);
        if (err < 0)
            return err;
        if (*pLen + err < *pLen)
            return TLV_ERR_OVERFLOW;

        // Write the length field
        TLV_LOG("len: %u\n\r", pToken[currTokenCnt].len);
        err = encode_length(&pDestCurr, END-pDestCurr, pToken[currTokenCnt].len);
        if (err < 0)
            return err;
        if (*pLen + err < *pLen)
            return TLV_ERR_OVERFLOW;

        // Copy the value
        TLV_LOG("val: ");
        TLV_LOG_HEX(pToken[currTokenCnt].val, pToken[currTokenCnt].len);
        TLV_LOG_LINE();
        const uint8_t* v = pToken[currTokenCnt].val;
        const uint8_t* const VAL_END = v + pToken[currTokenCnt].len;
        while (v < VAL_END) {
            // Make sure not to overrun the buffer
            if (pDestCurr >= END)
                return TLV_ERR_NOMEM;

            *pDestCurr++ = *v++;
        }
    }

    // Return total serialized length
    return *pLen = pDestCurr-BEGIN;
}

