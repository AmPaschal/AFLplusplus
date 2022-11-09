/*
   american fuzzy lop++ - postprocessor for PNG
   ------------------------------------------

   Originally written by Michal Zalewski

   Copyright 2015 Google Inc. All rights reserved.
   Adapted to the new API, 2020 by Dominik Maier

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   See post_library.so.c for a general discussion of how to implement
   postprocessors. This specific postprocessor attempts to fix up PNG
   checksums, providing a slightly more complicated example than found
   in post_library.so.c.

   Compile with:

     gcc -shared -Wall -O3 post_library_png.so.c -o post_library_png.so -lz

 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>
#include <arpa/inet.h>
#include "alloc-inl.h"

#include "custom_mutator_helpers.h"

/* A macro to round an integer up to 4 kB. */

#define UP4K(_i) ((((_i) >> 12) + 1) << 12)

typedef struct my_mutator {

  afl_t *afl;

} my_mutator_t;

void *afl_custom_init(afl_t *afl, unsigned int seed) {

   my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  data->afl = afl;

  return data;

}

size_t afl_custom_post_process(my_mutator_t *data, const unsigned char *in_buf,
                               unsigned int          len,
                               const unsigned char **out_buf) {

  
}

/* Gets called afterwards */
void afl_custom_deinit(post_state_t *data) {

  free(data->buf);
  free(data);

}

