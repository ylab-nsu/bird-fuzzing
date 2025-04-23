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
        __builtin_trap();
    }

    uint32_t asn;
    if (!as_path_get_first(as_path, &asn) || asn != last_prepended) {
        __builtin_trap();  
    }

    if (!as_path_get_last(as_path, &asn) || asn != first_prepended) {
        __builtin_trap();
    }

    lp_flush(tmp_linpool);

    return 0;  
}

#define MAX_BUF_SIZE 256

int
fuzz_path_format( uint8_t *data, size_t size)
{
  if (size < 4 || size > 252) {
    return -1;
  }

  struct adata empty_as_path = {};
  struct adata *as_path = &empty_as_path; 

  for (size_t i = 0; i + 4 < size; i += 4) {
    u32 asn;
    memcpy(&asn, data + i, sizeof(u32));

    as_path = as_path_prepend(tmp_linpool, as_path, asn);
  }
  byte buf[MAX_BUF_SIZE] = {};
  as_path_format(&empty_as_path, buf, MAX_BUF_SIZE);
  
  //empty buffer case
  if (strcmp(buf, "") != 0) {
    __builtin_trap();  
  }
  
  as_path_format(as_path, buf, MAX_BUF_SIZE);
  //if path is exists then check that path is not empty
  if (as_path != &empty_as_path && strlen(buf) == 0) {
    __builtin_trap(); // unexpected empty buffer
  }

  tmp_flush();

  return 1;
}