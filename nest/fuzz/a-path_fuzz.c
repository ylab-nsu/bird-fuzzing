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

static int
count_asn_in_array(const u32 *array, u32 asn)
{
  int counts_of_contains = 0;
  int u;
  for (u = 0; u < AS_PATH_LENGTH; u++)
    if (array[u] == asn)
	counts_of_contains++;
  return counts_of_contains;
}

int 
fuzz_path_include(uint8_t *data, size_t size) {
  struct adata empty_as_path = {};
  struct adata *as_path = &empty_as_path;

  u32 as_nums[AS_PATH_LENGTH] = {};
  int i;
  
  if (size < AS_PATH_LENGTH * sizeof(u32)) {
    return -1;
  }

  for (i = 0; i < AS_PATH_LENGTH; i++)
  {
    u32 val;
    for (int j = 0; j < 4; j++) {
      val = (val << 8) | data[i * 4 + j];
    }
    as_nums[i] = val;
    as_path = as_path_prepend(tmp_linpool, as_path, val);
  }


  for (i = 0; i < AS_PATH_LENGTH; i++)
  {
    int counts_of_contains = count_asn_in_array(as_nums, as_nums[i]);
    if (!as_path_contains(as_path, as_nums[i], counts_of_contains)) {
      __builtin_trap();  
    }

    struct f_val v = { .type = T_INT, .val.i = as_nums[i] };
    if (as_path_filter(tmp_linpool, as_path, &v, 0) == NULL) {
      __builtin_trap();  
    }
    if (as_path_filter(tmp_linpool, as_path, &v, 1) == NULL) {
      __builtin_trap();
    }
  }

  for (i = 0; i < 10000; i++)
  {
    u32 test_val = i;
    int counts_of_contains = count_asn_in_array(as_nums, test_val);
    int result = as_path_contains(as_path, test_val, (counts_of_contains == 0 ? 1 : counts_of_contains));

    if (counts_of_contains) {
      if (!result) {
        __builtin_trap();
      }
    } else {
      if (result != 0) {
        __builtin_trap();
      }
    }
  }

  tmp_flush();
  return 0;
}