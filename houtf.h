/*
Copyright (c) 2024-2025 Luke Philipsen

Permission to use, copy, modify, and/or distribute this software for
any purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED “AS IS” AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE
FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

/* Usage

  Do this:
    #define HOUTF_IMPLEMENTATION
  before you include this file in *one* C or C++ file to create the implementation.

  You can define HOUTF_DECL with
    #define HOUTF_DECL static
  or
    #define HOUTF_DECL extern
  to specify HOUTF function declarations as static or extern, respectively.
  The default specifier is extern.
*/

#ifndef HOUTF_H
    #define HOUTF_H

#include <stddef.h> /* NULL, size_t */
#include <string.h> /* memcpy() */

#ifndef HOUTF_DECL
    #define HOUTF_DECL
#endif /* HOUTF_DECL */

#ifdef __cplusplus
    extern "C" {
#endif /* __cpluspus */

/***************/
/* Definitions */

/**
 * Values representing the character encodings recognizef by houtf.
 */
typedef enum {
    HOUTF_ENCODING_UNKNOWN = 0, /**< Encoding is not known. This is assumed to be UTF-8 when encoding/decoding. */
    HOUTF_ENCODING_UTF8, /**< Variable-length character encoding using between one and four bytes per character. */
    HOUTF_ENCODING_UTF16BE, /**< Varaiable-length character encoding using two or four bytes. Big endian. */
    HOUTF_ENCODING_UTF16LE, /**< Varaiable-length character encoding using two or four bytes. Little endian. */
} houtf_encoding_t;

/**
 * A single character in both encoded and unencoded forms along with metadata.
 */
typedef struct {
    unsigned encoded; /* Character as it appeared in the source. In other words, the original, encoded character. */
    unsigned codepoint; /* Unicode codepoint of the character. In other words, the decoded character. */
    size_t bytes; /* Number of eight-bit bytes of the encoded character, in the [1, 4] range */
    houtf_encoding_t encoding; /**< Character encoding (UTF-8, UTF-16BE, etc.) used by the raw character. */
} houtf_char_t;

/**
 * Detect the character encoding of a string by searching its initial bytes for possible UTF byte order marks (BOMs).
 * As BOMs are typically prepended to text files, the given string would typicaly be the start of the file's content.
 *
 * @param str Pointer to search for a byte order mark.
 * @param bytes Number of bytes in the string.
 * @return Enumeration value indiciating the character encoding of the content
 */
HOUTF_DECL houtf_encoding_t houtf_detect_bom(const char* str, size_t bytes);

/**
 * Get the length of the byte order mark (BOM) of the given character encoding.
 *
 * @param encoding Character encoding of the BOM.
 */
HOUTF_DECL size_t houtf_bom_len(houtf_encoding_t encoding);

/**
 * Decode a single character assuming UTF-8. The given string should point to the first byte of the character to decode.
 *
 * @param str Pointer to the first byte of the character.
 * @param bytes Number of bytes in the string.
 * @return A structure containing the character's raw value, decoded value, number of bytes, and encoding.
 */
HOUTF_DECL houtf_char_t houtf_decode(const char* str, size_t bytes);

/**
 * Decode a single character explicitly given the expected character encoding. The given string should point to the
 * first byte of the character to decode.
 *
 * @param str Pointer to the first byte of the character.
 * @param bytes Number of bytes in the string.
 * @param encoding Encoding of the character.
 * @return A structure containing the character's raw value, decoded value, number of bytes, and encoding.
 */
HOUTF_DECL houtf_char_t houtf_decode_e(const char* str, size_t bytes, houtf_encoding_t encoding);

/**
 * Encode a single character codepoint as UTF-8.
 *
 * @param codepoint Unicode codepoint of the character.
 * @return A structure containing the character's encoded value, unencoded codepoint, number of bytes, and encoding.
 */
HOUTF_DECL houtf_char_t houtf_encode(unsigned codepoint);

/**
 * Encode a single character codepoint as the given character encoding.
 *
 * @param codepoint Unicode codepoint of the character.
 * @param encoding Character encoding to use.
 * @return A structure containing the character's encoded value, unencoded codepoint, number of bytes, and encoding.
 */
HOUTF_DECL houtf_char_t houtf_encode_e(unsigned codepoint, houtf_encoding_t encoding);

/**
 * Appends a copy of the UTF-8 'source' string to the UTF-8 'destination' string. The terminating null character in
 * 'destination' is overwritten by the first character of 'source,' and a null character is included at the end of the
 * new string formed by the concatenation of both in 'destination.'
 *
 * @param destination Pointer to the destination array, which should contain a UTF-8 string, and be large enough to
 *                    contain the concatenated resulting string.
 * @param source UTF-8 string to be appended. This should not overlap 'destination.'
 * @return 'destination' is returned.
 */
HOUTF_DECL char* houtf_strcat(char* destination, const char* source);

/**
 * Appends a copy of the 'source' string to the 'destination' string. The terminating null character in 'destination' is
 * overwritten by the first character of 'source,' and a null character is included at the end of the new string formed
 * by the concatenation of both in 'destination.'
 *
 * @param destination Pointer to the destination array, which should contain a string, and be large enough to contain
 *                    the concatenated resulting string.
 * @param destination_encoding Character encoding of the destination string.
 * @param source String to be appended. This should not overlap 'destination.'
 * @param source_encoding Character encoding of the source string.
 * @return 'destination' is returned.
 */
HOUTF_DECL char* houtf_strcat_e(char* destination, houtf_encoding_t destination_encoding, const char* source,
    houtf_encoding_t source_encoding);

/**
 * Returns a pointer to the first occurrence of 'codepoint' in the UTF-8 string 'str.'
 * The terminating null character is considered part of the string. Therefore, it can also be located.
 *
 * @param str UTF-8 string to be scanned.
 * @param codepoint Character to be located as its Unicode codepoint.
 * @return A pointer to the first byte of the first occurrence of 'codepoint' in 'str.' If the character is not found, a
 *         null pointer is returned.
 */
HOUTF_DECL const char* houtf_strchr(const char* str, unsigned codepoint);

/**
 * Returns a pointer to the first occurrence of 'codepoint' in the string 'str.'
 * The terminating null character is considered part of the string. Therefore, it can also be located.
 *
 * @param str String to be scanned.
 * @param codepoint Character to be located.
 * @param str_encoding Character encoding of the string.
 * @return A pointer to the first byte of the first occurrence of 'codepoint' in 'str.' If the character is not found, a
 *         null pointer is returned.
 */
HOUTF_DECL const char* houtf_strchr_e(const char* str, unsigned codepoint, houtf_encoding_t str_encoding);

/**
 * Compares the UTF-8 string 'str1' to UTF-8 string 'str2.'
 * This function starts comparing the first character of each string. If they are equal to each other, it continues with
 * the following pairs until the characters differ or until a terminating null character is reached.
 * This function performs a comparison of decoded vlue of the characters.
 *
 * @param str1 UTF-8 string to be compared.
 * @param str2 UTF-8 string to be compared.
 * @return Returns a value indicating the relationship between the strings. A value less than zero indicates the first
 *         character that does not match has a lower value in 'str1' than in 'str2.' A value greater than zero indicates
 *         the first character that does not match has a greater value in 'str1' than in 'str2'. Zero inidicates the
 *         contents of both strings are equal.
 */
HOUTF_DECL int houtf_strcmp(const char* str1, const char* str2);

/**
 * Compares the string 'str1' to string 'str2.'
 * This function starts comparing the first character of each string. If they are equal to each other, it continues with
 * the following pairs until the characters differ or until a terminating null character is reached.
 * This function performs a comparison of decoded vlue of the characters.
 *
 * @param str1 String to be compared.
 * @param str1_encoding Character encoding of 'str1'.
 * @param str2 String to be compared.
 * @param str2_encoding Character encoding of 'str2'.
 * @return Returns a value indicating the relationship between the strings. A value less than zero indicates the first
 *         character that does not match has a lower value in 'str1' than in 'str2.' A value greater than zero indicates
 *         the first character that does not match has a greater value in 'str1' than in 'str2'. Zero inidicates the
 *         contents of both strings are equal.
 */
HOUTF_DECL int houtf_strcmp_e(const char* str1, houtf_encoding_t str1_encoding, const char* str2,
    houtf_encoding_t str2_encoding);

/**
 * Returns the length of the UTF-8 string 'str.'
 * The length of a string is determiend by the terminator null character: a string is as long as the number of
 * characters between the beginning of the string and the terminating charcter (without including the terminating null
 * character itself).
 *
 * @param str A UTF-8 string.
 * @return The length of the string in characters.
 */
HOUTF_DECL size_t houtf_strlen(const char* str);

/**
 * Returns the length of the string 'str.'
 * The length of a string is determiend by the terminator null character: a string is as long as the number of
 * characters between the beginning of the string and the terminating charcter (without including the terminating null
 * character itself).
 *
 * @param str A string.
 * @param encoding Character encoding of the string.
 * @return The length of the string in characters.
 */
HOUTF_DECL size_t houtf_strlen_e(const char* str, houtf_encoding_t encoding);

/**
 * Returns a pointer to the first occurrence of UTF-8 string 'str2' in UTF-8 string 'str1,' or a null pointer if 'str2'
 * is not part of 'str1.'
 * The matching process does not include the terminating null characters, but it stops there.
 *
 * @param str1 UTF-8 string to be scanned.
 * @param str2 UTF-8 string contaiing the sequence of characters to match.
 * @return A pointer to the first occurrence in 'str1' of the entire sequence of characters specificied in 'str2,' or a
 *         null pointer if the sequence is not present in 'str1.'
 */
HOUTF_DECL const char* houtf_strstr(const char* str1, const char* str2);

/**
 * Returns a pointer to the first occurrence of 'str2' in 'str1,' or a null pointer if 'str2' is not part of 'str1.'
 * The matching process does not include the terminating null characters, but it stops there.
 *
 * @param str1 String to be scanned.
 * @param str1_encoding Character encoding of 'str1.'
 * @param str2 String contaiing the sequence of characters to match.
 * @param str2_encoding Character encoding of 'str2.'
 * @return A pointer to the first occurrence in 'str1' of the entire sequence of characters specificied in 'str2,' or a
 *         null pointer if the sequence is not present in 'str1.'
 */
HOUTF_DECL const char* houtf_strstr_e(const char* str1, houtf_encoding_t str1_encoding, const char* str2,
    houtf_encoding_t str2_encoding);

#ifdef __cplusplus
    }
#endif /* __cplusplus */

#ifdef HOUTF_IMPLEMENTATION

/******************/
/* Implementation */

houtf_encoding_t houtf_detect_bom(const char* str, size_t bytes)
{
    /* UTF byte order marks (BOMs) are simple magic numbers prepended to files. They can be detected by comparing the */
    /* first 16 to 32 bits again those magic numbers. */

    if (str != NULL)
    {
        /* The UTF-8 BOM is EF BB BF */
        if (bytes >= 3 && (str[0] & 0xFF) == 0xEF && (str[1] & 0xFF) == 0xBB && (str[2] & 0xFF) == 0xBF)
            return HOUTF_ENCODING_UTF8;
        /* The UTF-16BE BOM is FE FF */
        else if (bytes >= 2 && (str[0] & 0xFF) == 0xFE && (str[1] & 0xFF) == 0xFF)
            return HOUTF_ENCODING_UTF16BE;
        /* The UTF-16LE BOM is FF FE */
        else if (bytes >= 2 && (str[0] & 0xFF) == 0xFF && (str[1] & 0xFF) == 0xFE)
            return HOUTF_ENCODING_UTF16LE;
    }

    /* If this function hasn't returned yet, there are three possible reasons: 1) the string pointer is null, 2) the */
    /* number of characters in the string is too small to contain a BOM, or 3) there's simply no BOM at the start of */
    /* the string. The BOM cannot be detected. */
    return HOUTF_ENCODING_UNKNOWN;
}

size_t houtf_bom_len(houtf_encoding_t encoding)
{
    switch (encoding)
    {
    case HOUTF_ENCODING_UNKNOWN:
    default:
        return 0;

    case HOUTF_ENCODING_UTF8:
        return 3; /* UTF-8's BOM (EF BB BF) is three bytes long */

    case HOUTF_ENCODING_UTF16BE:
    case HOUTF_ENCODING_UTF16LE:
        return 2; /* UTF-16BE's BOM (FE FF) and UTF-16LE's BOM (FF FE) are both two bytes long */
    }
}

houtf_char_t houtf_decode(const char* str, size_t bytes)
{
    return houtf_decode_e(str, bytes, HOUTF_ENCODING_UTF8);
}

houtf_char_t houtf_decode_e(const char* str, size_t bytes, houtf_encoding_t encoding)
{
    houtf_char_t c = {/* encoded: */ 0, /* codepoint: */ 0, /* bytes: */ 0, /* encoding: */ HOUTF_ENCODING_UNKNOWN};

    switch (encoding)
    {
    case HOUTF_ENCODING_UNKNOWN:
        c.bytes = 1;
    break;
    case HOUTF_ENCODING_UTF8:
        /* The first byte of a UTF-8 character can can begin with one of four bit patterns, each indicating the */
        /* number of remaining bytes: 0XXXXXXX = 1 byte, 110XXXXX = 2 bytes, 1110XXXX = 3 bytes, 11110XXX = 4 bytes. */
        /* NOTE: UTF-8 is *big* endian. */
        if (((str[0] >> 7) & 0x01) == 0x00)
            c.bytes = 1;
        else if (((str[0] >> 5) & 0x07) == 0x06)
            c.bytes = 2;
        else if (((str[0] >> 4) & 0x0F) == 0x0E)
            c.bytes = 3;
        else if (((str[0] >> 3) & 0x1F) == 0x1E)
            c.bytes = 4;
    break;
    case HOUTF_ENCODING_UTF16BE:
        /* UTF-16 characters are either two bytes or four bytes where the four-byte characters are encoded such that */
        /* the first two bytes begin with 110110XX and the second with 110111XX. The rest are two-byte characters. */
        if (((str[0] >> 2) & 0x3F) == 0x36 && ((str[2] >> 2) & 0x3F) == 0x37)
            c.bytes = 4;
        else
            c.bytes = 2;
    break;
    case HOUTF_ENCODING_UTF16LE:
        /* UTF-16LE (Little Endian) is just like UTF-16BE (Big Endian) but the most and least significant bytes in */
        /* any 16-bit sequence are swapped. (Technically, a byte isn't defined as eight bits but it is in practice.) */
        if (((str[1] >> 2) & 0x3F) == 0x36 && ((str[3] >> 2) & 0x3F) == 0x37)
            c.bytes = 4;
        else
            c.bytes = 2;
    break;
    }

    /* If the string doesn't have enough bytes in it to decode this character */
    if (c.bytes > bytes)
    {
        /* Return early with all values zeroed */
        c.bytes = 0;
        return c;
    }

    switch (encoding)
    {
    case HOUTF_ENCODING_UNKNOWN:
        c.codepoint = str[0];
    break;
    case HOUTF_ENCODING_UTF8:
        if (c.bytes == 1)
        {
            /* One-byte UTF-8 characters are encoded as 0XXXXXXX where the Xs represent the bits of the character's */
            /* value. For all decoding, we want to grab only those bits and transform them into an integer. */
            /* The method here takes one byte from the string, uses a mask to zero out any bit that is not part of */
            /* resulting value, casts the masked byte to an unsigned 32-bit integer, shifts those bits to the left to */
            /* place them at the indexes they're expected in the value, and then bitwise ORs these components into a */
            /* single unsigned 32-bit integer. This one-byte case does not need any shift but the remaining cases do. */
            c.codepoint = (unsigned)(str[0] & 0x7F);
        }
        else if (c.bytes == 2)
        {
            /* Two-byte UTF-8 characters are encoded as 110XXXXX 10XXXXXX */
            c.codepoint = ((unsigned)(str[0] & 0x1F) << 6) | ((unsigned)(str[1] & 0x3F) << 0);
        }
        else if (c.bytes == 3)
        {
            /* Three-byte UTF-8 characters are encoded as 1110XXXX 10XXXXXX 10XXXXXX */
            c.codepoint = ((unsigned)(str[0] & 0x0F) << 12) | ((unsigned)(str[1] & 0x3F) << 6) |
                          ((unsigned)(str[2] & 0x3F) << 0);
        }
        else if (c.bytes == 4)
        {
            /* Four-byte UTF-8 characters are encoded as 11110XXX 10XXXXXX 10XXXXXX 10XXXXXX */
            c.codepoint = ((unsigned)(str[0] & 0x07) << 18) | ((unsigned)(str[1] & 0x3F) << 12) |
                          ((unsigned)(str[2] & 0x3F) << 6)  | ((unsigned)(str[3] & 0x3F) << 0);
        }
    break;
    case HOUTF_ENCODING_UTF16BE:
        if (c.bytes == 2)
        {
            /* Concatenate the two bytes together to retrieve the original value */
            c.codepoint = ((unsigned)str[0] << 8) | ((unsigned)str[1] << 0);
        }
        else if (c.bytes == 4)
        {
            /* Four-byte UTF-16 characters are encoded as 110110XX XXXXXXXX 110111XX XXXXXXXX after first subtracting */
            /* 0x00010000 from the value. Here, that subtracted value is reconstructed and 0x00010000 is added back. */
            c.codepoint = (((unsigned)(str[0] & 0x03) << 18) | ((unsigned)str[1] << 16) |
                           ((unsigned)(str[2] & 0x03) << 8)  | ((unsigned)str[3] << 0)) + 0x00010000;
        }
    break;
    case HOUTF_ENCODING_UTF16LE:
        if (c.bytes == 2)
            c.codepoint = ((unsigned)str[1] << 8) | ((unsigned)str[0] << 0);
        else if (c.bytes == 4)
        {
            c.codepoint = (((unsigned)(str[1] & 0x03) << 18) | ((unsigned)str[0] << 16) |
                           ((unsigned)(str[3] & 0x03) << 8)  | ((unsigned)str[2] << 0)) + 0x00010000;
        }
    break;
    }

    memcpy(&(c.encoded), str, c.bytes); /* Copy the bytes of the character from the pointed-to string into c.encoded */

    return c;
}

houtf_char_t houtf_encode(unsigned codepoint)
{
    return houtf_encode_e(codepoint, HOUTF_ENCODING_UTF8);
}

houtf_char_t houtf_encode_e(unsigned codepoint, houtf_encoding_t encoding)
{
    houtf_char_t c = {/* encoded: */ 0, /* codepoint: */ 0, /* bytes: */ 0, /* encoding: */ HOUTF_ENCODING_UNKNOWN};

    /* This variable will make it easier to assign values to 'c.endoded' without difficult-to-read casts */
    char* str = (char*)&(c.encoded);

    switch (encoding) {
    case HOUTF_ENCODING_UNKNOWN: /* If the encoding is somehow not specified, assume UTF-8 */
    case HOUTF_ENCODING_UTF8:
        if (codepoint <= 0x0000007F) /* If the codepoint will fit into one byte */
        {
            c.encoded = codepoint;
            c.bytes = 1;
        }
        else if (codepoint >= 0x000080 && codepoint<= 0x000007FF) /* If the codepoint will fit into two bytes */
        {
            /* For codepoints with bits XXXXXAAA AABBBBBB we want to transform them to the form 110AAAAA 10BBBBBB. */
            /* The method here treats c.encoded as an array of unsigned, eight-bit integers. This is done to assign */
            /* bytes individually for the sake of endianness where UTF-8 is big endian. The codepoint is masked in */
            /* order to zero any bits that are not used in the byte being assigned, then shifted all the way to the */
            /* right. The prefixed "0xC0" and "0x80" bitwise ORs prepend the UTF-8 markers 110 and 10, respectively. */
            str[0] = 0xC0 | (char)((codepoint & 0x0000007C0) >> 6); /* 110AAAAAA */
            str[1] = 0x80 | (char)((codepoint & 0x0000000FF) >> 0); /* 10BBBBBB */
            c.bytes = 2;
        }
        else if ((codepoint >= 0x00000800 && codepoint <= 0x0000D7FF) ||
                (codepoint >= 0x0000E000 && codepoint <= 0x0000FFFF))
        {
            /* For a codepoint with bits AAAABBBB BBCCCCCC we want 1110AAAA 10BBBBBB 10CCCCCC */
            str[0] = 0xE0 | (char)((codepoint & 0x0000F000) >> 12); /* 1110AAAA */
            str[1] = 0x80 | (char)((codepoint & 0x00000FC0) >> 6);  /* 10BBBBBB */
            str[2] = 0x80 | (char)((codepoint & 0x0000003F) >> 0);  /* 10CCCCCC */
            c.bytes = 3;
        }
        else if (codepoint >= 0x00010000 && codepoint <= 0x0010FFFF) {
            /* For a codepoint with bits XXXAAABB BBBBCCCC CCDDDDDD we want 11110AAA 10BBBBBB 10CCCCCC 10DDDDDD */
            str[0] = 0xF0 | (char)((codepoint & 0x001C0000) >> 18); /* 11110AAA */
            str[1] = 0x80 | (char)((codepoint & 0x0003F000) >> 12); /* 10BBBBBB */
            str[2] = 0x80 | (char)((codepoint & 0x00000FC0) >> 6);  /* 10CCCCCC */
            str[3] = 0x80 | (char)((codepoint & 0x0000003F) >> 0);  /* 10DDDDDD */
            c.bytes = 4;
        }
        else /* If the codepoint is not valid */
            c.bytes = 0; /* Don't even try */
    break;
    case HOUTF_ENCODING_UTF16BE:
        if (codepoint <= 0x0000D7FF || (codepoint >= 0x0000E000 && codepoint <= 0x0000FFFF)) /* Fits in two bytes */
        {
            str[0] = (char)((codepoint & 0x0000FF00) >> 8);
            str[1] = (char) (codepoint & 0x000000FF);
            c.bytes = 2;
        }
        else if (codepoint >= 0x00010000 && codepoint <= 0x0010FFFF) /* If the codepoint fits in four bytes */
        {
            /* For codepoint - 0x00010000 with bits XXXXXXXX XXXXAABB BBBBBBCC DDDDDDDD we want to transform the bits */
            /* to the form 110110AA BBBBBBBB 110111CC DDDDDDDD. When decoded, as per UTF-16, 0x00010000 is added. */
            /* The prefixed "0xD8" and "0xDC" bitwise ORs prepend the UTF-16 markers 110110 and 110111, respectively. */
            codepoint -= 0x00010000;
            str[0] = 0xD8 | (char)((codepoint & 0x000C0000) >> 20); /* 110110AA */
            str[1] =        (char)((codepoint & 0x0003FC00) >> 18); /* BBBBBBBB */
            str[2] = 0xDC | (char)((codepoint & 0x00000300) >> 8);  /* 110111CC */
            str[3] =        (char)((codepoint & 0x000000FF) >> 0);  /* DDDDDDDD */
            c.bytes = 4;
        }
        else /* If the codepoint is not valid */
            c.bytes = 0; /* Don't even try */
    break;
    case HOUTF_ENCODING_UTF16LE:
        /* UTF-16LE (Little Endian) is just like UTF-16BE (Big Endian) with the reverse endianness meaning that the */
        /* operations here are identical to those above but the indexes have been changed to reflect endianness */
        if (codepoint <= 0x0000D7FF || (codepoint >= 0x0000E000 && codepoint <= 0x0000FFFF))
        {
            str[1] = (char)((codepoint & 0x0000FF00) >> 8);
            str[0] = (char)((codepoint & 0x000000FF) >> 0);
            c.bytes = 2;
        }
        else if (codepoint >= 0x00010000 && codepoint <= 0x0010FFFF)
        {
            codepoint -= 0x00010000;
            str[3] = 0xD8 | (char)((codepoint & 0x000C0000) >> 20); /* 110110AA */
            str[2] =        (char)((codepoint & 0x0003FC00) >> 18); /* BBBBBBBB */
            str[1] = 0xDC | (char)((codepoint & 0x00000300) >> 8);  /* 110111CC */
            str[0] =        (char)((codepoint & 0x000000FF) >> 0);  /* DDDDDDDD */
            c.bytes = 4;
        }
        else
            c.bytes = 0;
    break;
    }

    return c;
}

char* houtf_strcat(char* destination, const char* source)
{
    return houtf_strcat_e(destination, HOUTF_ENCODING_UTF8, source, HOUTF_ENCODING_UTF8);
}

char* houtf_strcat_e(char* destination, houtf_encoding_t destination_encoding, const char* source,
    houtf_encoding_t source_encoding)
{
    if (destination == NULL || source == NULL)
        return destination;

    /* Iterate through the current destination string to look for the null terminator, stopping there */
    char* id = destination; /* Destination iterator */
    houtf_char_t cd = houtf_decode_e(/* str: */ id, /* bytes: */ 4, /* encoding: */ destination_encoding);
    while (cd.codepoint != 0) /* While not at the destination's terminator */
    {
        id += cd.bytes; /* Iterate forward by the number of bytes used by the previous character */
        cd = houtf_decode_e(id, 4, destination_encoding);
    }

    /* Iterate through both strings, assigning values from the source string to the destination string */
    const char* is = source; /* Source iterator */
    houtf_char_t cs = {0, 0, 0, HOUTF_ENCODING_UNKNOWN}; /* Source character */
    do
    {
        cs = houtf_decode_e(/* str: */ is, /* bytes: */ 4, /* encoding: */ source_encoding);
        /* Reuse 'cd' to re-encode the character from the source and copy the character to the destination */
        cd = houtf_encode_e(/* codepoint: */ cs.codepoint, /* encoding: */ destination_encoding);
        memcpy(id, &(cd.encoded), cd.bytes);

        /* Iterate to the next character for both strings */
        is += cs.bytes;
        id += cs.bytes;
    }
    while (cs.codepoint != 0); /* While not at the source's terminator */

    return destination;
}

const char* houtf_strchr(const char* str, unsigned codepoint)
{
    return houtf_strchr_e(str, codepoint, HOUTF_ENCODING_UTF8);
}

const char* houtf_strchr_e(const char* str, unsigned codepoint, houtf_encoding_t str_encoding)
{
    if (str == NULL)
        return NULL;

    const char* i = str; /* Iterator */
    houtf_char_t c = {0, 0, 0, HOUTF_ENCODING_UNKNOWN}; /* Decoded character */
    do
    {
        c = houtf_decode_e(/* str: */ i, /* bytes: */ 4, /* encoding: */ str_encoding);
        if (c.codepoint == codepoint)
            return i;

        i += c.bytes; /* Iterate forward by the number of bytes used by the character */
    }
    while (c.codepoint != 0); /* While not at the string's terminator */

    return NULL;
}

int houtf_strcmp(const char* str1, const char* str2)
{
    return houtf_strcmp_e(str1, HOUTF_ENCODING_UTF8, str2, HOUTF_ENCODING_UTF8);
}

int houtf_strcmp_e(const char* str1, houtf_encoding_t str1_encoding, const char* str2, houtf_encoding_t str2_encoding)
{
    if (str1 == NULL && str2 == NULL)
        return 0;
    else if (str1 == NULL)
        return -1;
    else if (str2 == NULL)
        return 1;

    const char* i1 = str1; /* str1 iterator */
    const char* i2 = str2; /* str2 iterator */
    houtf_char_t c1 = {0, 0, 0, HOUTF_ENCODING_UNKNOWN}; /* str1 character */
    houtf_char_t c2 = {0, 0, 0, HOUTF_ENCODING_UNKNOWN}; /* str2 character */
    do
    {
        /* Decode the current character from strings in order to know their values and number of bytes */
        c1 = houtf_decode_e(/* str: */ i1, /* bytes: */ 4, /* encoding: */ str1_encoding);
        c2 = houtf_decode_e(i2, 4, str2_encoding);

        /* Iterate to the next character for both strings */
        i1 += c1.bytes;
        i2 += c2.bytes;
    }
    while (c1.codepoint != 0 && c1.codepoint == c2.codepoint); /* While equal and not at the terminator */

    return (int)(c1.codepoint - c2.codepoint);
}

size_t houtf_strlen(const char* str)
{
    return houtf_strlen_e(str, HOUTF_ENCODING_UTF8);
}

size_t houtf_strlen_e(const char* str, houtf_encoding_t encoding)
{
    if (str == NULL)
        return 0;

    size_t len = 0; /* Length, to be incremented each character */
    const char* i = str; /* Iterator */
    houtf_char_t c = houtf_decode_e(/* str: */ i, /* bytes: */ 4, /* encoding: */ encoding); /* Decoded character */
    while (c.codepoint != 0) /* While not at the string's terminator */
    {
        len += 1; /* Increment the length of the string by one */
        i += c.bytes; /* Iterate forward by the number of bytes used by the previous character */
        c = houtf_decode_e(i, 4, encoding); /* Decode the next character */
    }

    return len;
}

const char* houtf_strstr(const char* str1, const char* str2)
{
    return houtf_strstr_e(str1, HOUTF_ENCODING_UTF8, str2, HOUTF_ENCODING_UTF8);
}

const char* houtf_strstr_e(const char* str1, houtf_encoding_t str1_encoding, const char* str2,
    houtf_encoding_t str2_encoding)
{
    if (str1 == NULL || str2 == NULL)
        return NULL;

    const char* i1_0 = str1; /* Outer loop str1 iterator. Points to the start of the matching string, if it exists. */
    houtf_char_t c1 = houtf_decode_e(/* str: */ str1, /* bytes: */ 4, /* encoding: */ str1_encoding);
    houtf_char_t c2 = houtf_decode_e(str2, 4, str2_encoding);

    while (c1.codepoint != 0 && c2.codepoint != 0)
    {
        if (c1.codepoint == c2.codepoint)
        {
            const char* i1 = i1_0;
            const char* i2 = str2;
            do
            {
                c1 = houtf_decode_e(i1, 4, str1_encoding);
                c2 = houtf_decode_e(i2, 4, str2_encoding);

                if (c2.codepoint == 0)
                    return i1_0;

                i1 += c1.bytes;
                i2 += c2.bytes;
            }
            while (c1.codepoint == c2.codepoint);
        }

        i1_0 += c1.bytes;
        c1 = houtf_decode_e(i1_0, 4, str1_encoding);
    }

    return NULL;
}

#endif /* HOUTF_IMPLEMENTATION */

#endif /* HOUTF_H */
