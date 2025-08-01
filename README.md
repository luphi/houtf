# houtf

Header-Only UTF library written in portable ANSI C.


## Features

- Portable ANSI C (C89), tested with GCC (Windows and Linux), Clang (macOS), and MSVC
- Supports UTF-8, UTF-16BE, and UTF-16LE including their BOMs
- Decode and encode
- Implements the more popular string manipulation functions from C's standard library
- No dependencies beyond the C standard library


## Limitations

- Does not support UTF-32 (yet?)


## Usage

Define the implementation before including houtf.
``` c
#include <stdio.h> /* printf() */
#include <stdlib.h> /* EXIT_SUCCESS, NULL */
#include <string.h> /* strcpy() */

#define HOUTF_IMPLEMENTATION
#include "houtf.h"

int main(int argc, char** argv)
{
    /* Create some UTF-8 strings with relatively high Unicode values */
    /* This string in a more readable form is: 元気で明るく、朗らかな性格である。*/
    const char* outer = "\xe5\x85\x83\xe6\xb0\x97\xe3\x81\xa7\xe6\x98\x8e\xe3\x82\x8b\xe3\x81\x8f\xe3\x80\x81\xe6\x9c"
                        "\x97\xe3\x82\x89\xe3\x81\x8b\xe3\x81\xaa\xe6\x80\xa7\xe6\xa0\xbc\xe3\x81\xa7\xe3\x81\x82\xe3"
                        "\x82\x8b\xe3\x80\x82";
    /* This is an excerpt from the previous string: 明るく */
    const char* inner = "\xe6\x98\x8e\xe3\x82\x8b\xe3\x81\x8f";

    /* Measuring the length of a string in characters */
    printf("\"%s\" is %lu characters long\n", outer, (unsigned long)houtf_strlen(outer));
    printf("\"%s\" is %lu characters long\n", inner, (unsigned long)houtf_strlen(inner));

    /* Comparing two strings that are not equal */
    if (houtf_strcmp(outer, inner) == 0)
        printf("\"%s\" is equal to \"%s\"\n", outer, inner);
    else
        printf("\"%s\" is NOT equal to \"%s\"\n", outer, inner);

    /* Comparing two strings that are equal */
    if (houtf_strcmp(outer, outer) == 0)
        printf("\"%s\" is equal to \"%s\"\n", inner, inner);
    else
        printf("\"%s\" is NOT equal to \"%s\"\n", inner, inner);

    /* Searching for one string within another */
    if (houtf_strstr(outer, inner) != NULL)
        printf("\"%s\" is inside \"%s\"\n", inner, outer);
    else
        printf("\"%s\" is NOT inside \"%s\"\n", inner, outer);

    /* Reversing the previous case */
    if (houtf_strstr(inner, outer) != NULL)
        printf("\"%s\" is inside \"%s\"\n", outer, inner);
    else
        printf("\"%s\" is NOT inside \"%s\"\n", outer, inner);

    /* Concatenation */
    char destination[32] = {0};
    strcpy(destination, inner);
    printf("\"%s\" + \"%s\" = \"%s\"\n", destination, inner, houtf_strcat(destination, inner));

    return EXIT_SUCCESS;
}

```
