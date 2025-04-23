#include "a-path_fuzz.h"

byte state = 0;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (state == 0) {
    char *arr[] = {""};
    bt_init(1, arr);
    state = 1;
  } 
  
  return fuzz_path_format(Data, Size);
}


