#include <stdint.h>
#include <stddef.h>
#include "rt_fib_test_my.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size % 5 != 0) {
    return -1;
  }


  return t_match_random_net(Data, Size);
}
