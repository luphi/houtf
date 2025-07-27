#include <stdio.h> /* FILE, fclose(), fopen(), fprintf(), fread(), printf(), stderr */
#include <stdlib.h> /* EXIT_FAILURE, EXIT_SUCCESS, NULL */

#include <string.h> /* TODO: delete */

#define HOUTF_IMPLEMENTATION
#include "houtf.h"

#define NUM_DOCUMENTS 4
#define CONTENT_BUFFERS_LENGTH 512

/* Simple strutcure pointing to the content of a file and holding some information about it */
typedef struct
{
    const char* file_name;
    const char* str;
    houtf_encoding_t encoding;
} document_t;

const char* encoding_to_string(houtf_encoding_t encoding)
{
    switch (encoding)
    {
    default:
    case HOUTF_ENCODING_UNKNOWN: return "unknown";
    case HOUTF_ENCODING_UTF8:    return "UTF-8";
    case HOUTF_ENCODING_UTF16BE: return "UTF-16BE";
    case HOUTF_ENCODING_UTF16LE: return "UTF-16LE";
    }
}

int main(int argc, char** argv)
{
    document_t documents[NUM_DOCUMENTS] = {0}; /* Information about the documents */
    documents[0].file_name = "ascii.txt";
    documents[1].file_name = "utf8_bom.txt";
    documents[2].file_name = "utf16be_bom.txt";
    documents[3].file_name = "utf16le_bom.txt";

    char contents[NUM_DOCUMENTS][CONTENT_BUFFERS_LENGTH] = {0}; /* Full contents of the documents */
    int from = 0;
    int to = NUM_DOCUMENTS - 1;
    if (argc > 1) /* If a specific index was passed as a CLI argument */
        from = to = atoi(argv[1]); /* No sanitation here. You're a programmer. Be smart. */

    int i;
    for (i = from; i <= to; i++)
    {
        /* Try to open the file and check if it failed */
        FILE* file;
        if ((file = fopen(documents[i].file_name, "r")) == NULL)
        {
            fprintf(stderr, "Failed to open document: \"%s\"\n", documents[i].file_name);
            return EXIT_FAILURE;
        }

        /* Try to read the contents of the file and check if it failed */
        size_t bytes_read;
        if ((bytes_read = fread(contents[i], 1, CONTENT_BUFFERS_LENGTH - 1, file)) == 0)
        {
            fprintf(stderr, "\n\nFailed to read document \"%s\", exiting...\n", documents[i].file_name);
            return EXIT_FAILURE;
        }

        fclose(file); /* The file's contents are in memory so it can be closed */
        contents[i][bytes_read] = '\0'; /* Null terminate the string to be safe */
        houtf_encoding_t encoding = houtf_detect_bom(contents[i], bytes_read);
        const char* str = contents[i] + houtf_bom_len(encoding);
        documents[i].str = str;
        documents[i].encoding = encoding;
        printf("---- Read document \"%s\" of %lu bytes and %lu characters with encoding %s\n", documents[i].file_name,
            (unsigned long)bytes_read, (unsigned long)houtf_strlen_e(str, encoding), encoding_to_string(encoding));
    }

    /* Go through all permutations and perform a string comparison */
    int exit_status = EXIT_SUCCESS;
    int j;
    for (i = from; i < NUM_DOCUMENTS; i++)
    {
        for (j = from; j < NUM_DOCUMENTS; j++)
        {
            if (i == j)
                continue; /* Don't compare one string against itself */

            document_t doc1 = documents[i];
            document_t doc2 = documents[j];
            if (houtf_strcmp_e(doc1.str, doc1.encoding, doc2.str, doc2.encoding) == 0)
            {
                printf("-- %s (%s) == %s (%s)\n", doc1.file_name, encoding_to_string(doc1.encoding), doc2.file_name,
                    encoding_to_string(doc2.encoding));
            }
            else
            {
                printf("!! %s (%s) != %s (%s)\n", doc1.file_name, encoding_to_string(doc1.encoding), doc2.file_name,
                    encoding_to_string(doc2.encoding));
                exit_status = EXIT_FAILURE;
            }
        }
    }

    return exit_status;
}
