#include <stdint.h>
#include <stddef.h>
#include "rt-fib_fuzz_utils.h"

int state = 0;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (state == 0) {
    char *arr[] = {"./obj/nest/fuzz/rt-fib_fuzz_natches.c"};
    bt_init(1, arr);
    bt_bird_init();
    bt_config_parse(BT_CONFIG_SIMPLE);
    state = 1;
  } 

  if ((Size % 5 != 0) || (Size == 0)) {
    return -1;
  }

  return t_match_random_net_mostly_negative(Data, Size);
}
