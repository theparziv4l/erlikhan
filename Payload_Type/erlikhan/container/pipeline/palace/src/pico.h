/* PICO tag-dispatch runtime. The blob layout is
 * [total_size u32][num_exports u32][tag,offset pairs][code];
 * offsets are relative to the code start. */
#ifndef PALACE_PICO_H
#define PALACE_PICO_H

#include "loader.h"

#define PICO_TAG_SETUP_HOOKS 0
#define PICO_TAG_SETUP_MEMORY 1

#endif
