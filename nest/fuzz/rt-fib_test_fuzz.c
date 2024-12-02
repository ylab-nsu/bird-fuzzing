#include <stdint.h>
#include <stddef.h>
// #include "rt_fib_test_my.h"
#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "nest/route.h"

int state = 0;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  

  if (state == 0) {
    char *arr[] = {"./obj/nest/rt-fib_test"};
    bt_init(1, arr);
    bt_bird_init();
    bt_config_parse(BT_CONFIG_SIMPLE);
    state = 1;
  } 
  //bt_test_suite(t_match_random_net, "Testing random prefix matching");

  // //bt_init(1, "./obj/nest/fuzz/rt-fib");
  // if ((Size % 5 != 0) || (Size == 0)) {
  //   return -1;
  // }
  // //bt_exit_value();
  return 0;
}


