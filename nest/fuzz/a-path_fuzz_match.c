#include "a-path_fuzz.h"

byte state = 0;

int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {

    if (state == 0) {
        char *arr[] = {""};
        bt_init(1, arr);
        state = 1;
    } 

    if (size == 0) return 1;

    return fuzz_as_path_match(data, size);
}