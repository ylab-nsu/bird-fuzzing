#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "nest/route.h"
#include <stdint.h>
#include <stddef.h>

#include "nest/route.h"
#include "nest/attrs.h"
#include "lib/resource.h"
#include "filter/data.h"
#include "lib/resource.h"

int fuzz_as_path_match(uint8_t *data, size_t size);
int fuzz_path_format(uint8_t *data, size_t size);
int fuzz_path_include(uint8_t *data, size_t size);
