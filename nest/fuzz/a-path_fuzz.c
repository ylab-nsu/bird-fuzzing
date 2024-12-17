#include "a-path_fuzz.h"

#define AS_PATH_LENGTH 1000

#if AS_PATH_LENGTH > AS_PATH_MAXLEN
#warning "AS_PATH_LENGTH should be <= AS_PATH_MAXLEN"
#endif

int 
fuzz_as_path_match(uint8_t *data, size_t size) {
    
    struct adata empty_as_path = {};
    struct adata *as_path = &empty_as_path;
    u32 first_prepended, last_prepended;
    first_prepended = last_prepended = 0;

    struct f_path_mask *mask = alloca(sizeof(struct f_path_mask) + AS_PATH_LENGTH * sizeof(struct f_path_mask_item));
    mask->len = AS_PATH_LENGTH;

    for (int i = AS_PATH_LENGTH - 1; i >= 0; i--) {
        uint32_t val = data[i % size];  
        as_path = as_path_prepend(tmp_linpool, as_path, val);  

        bt_debug("Prepending ASN: %10u \n", val);

        if (i == 0)
            last_prepended = val;
        if (i == AS_PATH_LENGTH - 1)
            first_prepended = val;

        mask->item[i].kind = PM_ASN;
        mask->item[i].asn = val;
    }

    if (!as_path_match(as_path, mask)) {
        free(mask);
        __builtin_trap();
    }

    uint32_t asn;
    if (!as_path_get_first(as_path, &asn) || asn != last_prepended) {
        free(mask);
        __builtin_trap();
  
    }

    if (!as_path_get_last(as_path, &asn) || asn != first_prepended) {
        free(mask);
        __builtin_trap();
 
    }

    return 0;  
}