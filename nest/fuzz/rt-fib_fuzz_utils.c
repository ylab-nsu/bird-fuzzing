/*
 *	BIRD -- Forwarding Information Base -- Tests
 *
 *	(c) 2023 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "rt-fib_fuzz_utils.h"
#include "stdlib.h"
#define PREFIXES_NUM 		  400000
#define PREFIX_TESTS_NUM 	200000

struct test_node
{
  int pos;
  struct fib_node n;
};

static inline int net_match(struct test_node *tn, net_addr *query, net_addr *data)
{ 
    return (tn->pos < PREFIXES_NUM) && net_equal(query, &data[tn->pos]); 
}

int get_number_of_ips(int type, int Size);

int
t_match_random_net_positive(const uint8_t *Data, size_t Size, int type)
{
  pool *p = rp_new(&root_pool, "FIB pool");
  int number_of_ips = get_number_of_ips(type, Size);

  net_addr *nets = bt_random_nets_from_data(type, number_of_ips, Data);

  /* init block */
  struct fib *f;
  f = malloc(sizeof(struct fib));
  if (f != NULL) {
    fib_init(f, &root_pool, type, sizeof(struct test_node), OFFSETOF(struct test_node, n), 4, NULL);
  } else {
    die("Net type %d not implemented", type);
  }

  for (int i = 0; i < number_of_ips; i++)
  {
    struct test_node *tn = fib_get(f, &nets[i]);
    if (tn->pos && !net_match(tn, &nets[i], nets)) {
      __builtin_trap();
    }
    tn->pos = i;
  }
    
  /* Test positive matches */
  for (int j = 0; j < number_of_ips; j++)
  {
    struct test_node *tn = fib_find(f, &nets[j]);
    if (!tn || !net_match(tn, &nets[j], nets)) {
      __builtin_trap();
    }
  } 


  fib_free(f);
  free(f);
  rfree(p);
  tmp_flush();
  return 0;
}

int
t_match_random_net_mostly_negative(const uint8_t *Data, size_t Size)
{
  int type = NET_IP4;
  pool *p = rp_new(&root_pool, "FIB pool");
  int number_of_ips = Size / 5;
  net_addr *nets = bt_random_nets_from_data(type, number_of_ips, Data);

  /* init block */
  struct fib *f;
  f = malloc(sizeof(struct fib));
  if (f != NULL) {
    fib_init(f, &root_pool, type, sizeof(struct test_node), OFFSETOF(struct test_node, n), 4, NULL);
  }

  for (int i = 0; i < number_of_ips; i++)
  {
    struct test_node *tn = fib_get(f, &nets[i]);
    if (tn->pos && !net_match(tn, &nets[i], nets)) {
      __builtin_trap();
    }
    tn->pos = i;
  }

  /*Test (mostly) negative matches */
  for (int i = 0; i < PREFIX_TESTS_NUM; i++)
  {
    net_addr net;
    bt_random_net(&net, type);// TO DO change this (do determine)

    struct test_node *tn = fib_find(f, &net);
    if (tn && !net_match(tn, &net, nets)) {
      __builtin_trap();
    }
  }

  fib_free(f);
  free(f);
  rfree(p);
  tmp_flush();
  return 0;
}


int
t_match_random_net_only_negative(const uint8_t *Data, size_t Size, int type)
{
  pool *p = rp_new(&root_pool, "FIB pool");
  int number_of_ips = get_number_of_ips(type, Size);

  /* init block */
  struct fib *f;
  f = malloc(sizeof(struct fib));
  if (f != NULL) {
    fib_init(f, &root_pool, type, sizeof(struct test_node), OFFSETOF(struct test_node, n), 4, NULL);
  } else {
    die("Net type %d not implemented", type);
  }

  /*Test (only) negative matches */
  net_addr *net = bt_random_nets_from_data(type, number_of_ips, Data);
  for (int i = 0; i < number_of_ips; i++) {
    struct test_node *tn = fib_find(f, &net[i]);
    if (tn) {
      __builtin_trap();
    }
  }


  fib_free(f);
  free(f);
  rfree(p);
  tmp_flush();
  return 0;
}

int get_number_of_ips(int type, int Size) {
  switch (type) {
    case NET_IP4:
      return Size / 5;
    case NET_IP6:
      return Size / 17;
    default:
      die("Net type %d not implemented", type);
  }
}
