#include <stdio.h> /* FILE, fclose(), fopen(), fprintf(), fread(), printf(), stderr */
#include <stdlib.h> /* EXIT_FAILURE, EXIT_SUCCESS, NULL */
#include <string.h> /* memset(), strcpy() */

#define HOUTF_IMPLEMENTATION
#include "houtf.h"

#define FILE_NAME_BUFFER_LENGTH 16
#define CONTENT_BUFFER_LENGTH 128

static const char* encoding_to_string(houtf_encoding_t encoding) {
    switch (encoding) {
    default:
    case HOUTF_ENCODING_UNKNOWN: return "unknown";
    case HOUTF_ENCODING_UTF8:    return "UTF-8";
    case HOUTF_ENCODING_UTF16BE: return "UTF-16BE";
    case HOUTF_ENCODING_UTF16LE: return "UTF-16LE";
    }
}

enum {
    INDEX_UTF_8 = 0, /* Corresponds to utf8.txt, a UTF-8 file with a BOM */
    INDEX_UTF_16_BE, /* Corresponds to utf16be.txt, a UTF-16 BE file with a BOM*/
    INDEX_UTF_16_LE, /* Corresponds to utf16le.txt, a UTF-16 LE file with a BOM */
    NUM_DOCUMENTS /* Not an index - indicates the number of documents to test with */
};

int main(void) {
    unsigned int codepoint;
    const char *str1, *str2, *str3;
    houtf_char_t c1, c2, c3;
    int exit_status, i, j;
    char file_names[NUM_DOCUMENTS][FILE_NAME_BUFFER_LENGTH];
    char contents[NUM_DOCUMENTS][CONTENT_BUFFER_LENGTH];
    houtf_encoding_t encodings[NUM_DOCUMENTS];

    /* Phase 0: Initialize variables by assigning everything to zero or equivalent */
    codepoint = 0;
    str1 = str2 = str3 = NULL;
    c1.codepoint = c1.encoded = c2.codepoint = c2.encoded = c3.codepoint = c3.encoded = 0;
    c1.bytes = c2.bytes = c3.bytes = 0;
    c1.encoding = c2.encoding = c3.encoding = HOUTF_ENCODING_UNKNOWN;
    for (i = 0; i < NUM_DOCUMENTS; i++) {
        memset(file_names[i], '\0', FILE_NAME_BUFFER_LENGTH);
        memset(contents[i], '\0', CONTENT_BUFFER_LENGTH);
        encodings[i] = HOUTF_ENCODING_UNKNOWN;
    }
    exit_status = EXIT_SUCCESS;

    /* Phase 1: Check encoded and decoded values against known ones for specific codepoints */
    codepoint = 0x0024; /* $ */
    str1 = "\x24"; /* UTF-8 */
    str2 = "\x00\x24"; /* UTF-16 BE */
    str3 = "\x24\x00"; /* UTF-16 LE */
    c1 = houtf_decode_e(/* str: */ str1, /* bytes: */ 1, /* encoding: */ HOUTF_ENCODING_UTF8);
    c2 = houtf_decode_e(/* str: */ str2, /* bytes: */ 2, /* encoding: */ HOUTF_ENCODING_UTF16BE);
    c3 = houtf_decode_e(/* str: */ str3, /* bytes: */ 2, /* encoding: */ HOUTF_ENCODING_UTF16LE);
    if (c1.codepoint != codepoint || c2.codepoint != codepoint || c3.codepoint != codepoint) {
        printf("!!!! U+0024 - fail\n");
        exit_status = EXIT_FAILURE;
    } else
        printf("---- U+0024 - pass\n");
    codepoint = 0x20AC; /* € */
    str1 = "\xe2\x82\xac"; /* UTF-8 */
    str2 = "\x20\xac"; /* UTF-16 BE */
    str3 = "\xac\x20"; /* UTF-16 LE */
    c1 = houtf_decode_e(/* str: */ str1, /* bytes: */ 3, /* encoding: */ HOUTF_ENCODING_UTF8);
    c2 = houtf_decode_e(/* str: */ str2, /* bytes: */ 2, /* encoding: */ HOUTF_ENCODING_UTF16BE);
    c3 = houtf_decode_e(/* str: */ str3, /* bytes: */ 2, /* encoding: */ HOUTF_ENCODING_UTF16LE);
    if (c1.codepoint != codepoint || c2.codepoint != codepoint || c3.codepoint != codepoint) {
        printf("!!!! U+20AC - fail\n");
        exit_status = EXIT_FAILURE;
    } else
        printf("---- U+20AC - pass\n");
    codepoint = 0x10437; /* 𐐷 */
    str1 = "\xf0\x90\x90\xb7"; /* UTF-8 */
    str2 = "\xd8\x01\xdc\x37"; /* UTF-16 BE */
    str3 = "\x01\xd8\x37\xdc"; /* UTF-16 LE */
    c1 = houtf_decode_e(/* str: */ str1, /* bytes: */ 4, /* encoding: */ HOUTF_ENCODING_UTF8);
    c2 = houtf_decode_e(/* str: */ str2, /* bytes: */ 4, /* encoding: */ HOUTF_ENCODING_UTF16BE);
    c3 = houtf_decode_e(/* str: */ str3, /* bytes: */ 4, /* encoding: */ HOUTF_ENCODING_UTF16LE);
    if (c1.codepoint != codepoint || c2.codepoint != codepoint || c3.codepoint != codepoint) {
        printf("!!!! U+10437 - fail\n");
        exit_status = EXIT_FAILURE;
    } else
        printf("---- U+10437 - pass\n");
    codepoint = 0x24B62; /* 𤭢 */
    str1 = "\xf0\xa4\xad\xa2"; /* UTF-8 */
    str2 = "\xd8\x52\xdf\x62"; /* UTF-16 BE */
    str3 = "\x52\xd8\x62\xdf"; /* UTF-16 LE */
    c1 = houtf_decode_e(/* str: */ str1, /* bytes: */ 4, /* encoding: */ HOUTF_ENCODING_UTF8);
    c2 = houtf_decode_e(/* str: */ str2, /* bytes: */ 4, /* encoding: */ HOUTF_ENCODING_UTF16BE);
    c3 = houtf_decode_e(/* str: */ str3, /* bytes: */ 4, /* encoding: */ HOUTF_ENCODING_UTF16LE);
    if (c1.codepoint != codepoint || c2.codepoint != codepoint || c3.codepoint != codepoint) {
        printf("!!!! U+24B62 - fail\n");
        exit_status = EXIT_FAILURE;
    } else
        printf("---- U+24B62 - pass\n");

    /* Phase 2: Compare files with identical content but different encodings */

    /* Copy the base file names of the test documents into an array */
    strcpy(file_names[INDEX_UTF_8], "utf8.txt");
    strcpy(file_names[INDEX_UTF_16_BE], "utf16be.txt");
    strcpy(file_names[INDEX_UTF_16_LE], "utf16le.txt");

    /* Load the files' contents to their own buffers and determine their encodings by BOM */
    for (i = 0; i < NUM_DOCUMENTS; i++) {
        FILE* file;
        size_t bytes_read;

        /* Try to open the file and check if it failed */
        if ((file = fopen(file_names[i], "r")) == NULL) {
            fprintf(stderr, "\n\nFailed to open document: \"%s\"\n", file_names[i]);
            exit_status = EXIT_FAILURE;
            continue;
        }

        /* Null terminate the whole content buffer to ensure the string is null terminated */
        memset(contents[i], '\0', CONTENT_BUFFER_LENGTH);

        /* Try to read the contents of the file and check if it failed */
        if ((bytes_read = fread(contents[i], 1, CONTENT_BUFFER_LENGTH, file)) == 0) {
            fprintf(stderr, "\n\nFailed to read document \"%s\", exiting...\n", file_names[i]);
            fclose(file);
            exit_status = EXIT_FAILURE;
            continue;
        }

        fclose(file); /* The file's contents are in memory so it can be closed */
        encodings[i] = houtf_detect_bom(contents[i], bytes_read); /* Determine encoding by byte order mark (BOM) */
        printf("     Read document \"%s\" of %lu bytes and %lu characters with encoding %s\n", file_names[i],
            (unsigned long)bytes_read, (unsigned long)houtf_strlen_e(contents[i], encodings[i]),
            encoding_to_string(encodings[i]));
    }

    /* Go through all permutations and perform a string comparison */
    for (i = 0; i < NUM_DOCUMENTS; i++)
    {
        for (j = 0; j < NUM_DOCUMENTS; j++)
        {
            const char *str1, *str2;

            if (i == j)
                continue; /* Don't compare one string against itself */

            /* Point to the beginnings of both strings, after their BOMs */
            str1 = contents[i] + houtf_bom_len(encodings[i]);
            str2 = contents[j] + houtf_bom_len(encodings[j]);
            if (houtf_strcmp_e(str1, encodings[i], str2, encodings[j]) != 0)
            {
                printf("!!!! %s != %s\n", file_names[i], file_names[j]);
                exit_status = EXIT_FAILURE;
            }
            else
                printf("---- %s == %s\n", file_names[i], file_names[j]);
        }
    }

    return exit_status;
}
