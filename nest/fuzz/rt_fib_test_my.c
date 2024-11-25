/*
 *	BIRD -- Forwarding Information Base -- Tests
 *
 *	(c) 2023 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "rt_fib_test_my.h"

#define TESTS_NUM		10
#define PREFIXES_NUM 		  400000
#define PREFIX_TESTS_NUM 	200000
#define PREFIX_BENCH_MAX 	1000000
#define PREFIX_BENCH_NUM 	10000000

struct test_node
{
  int pos;
  struct fib_node n;
};

static inline int net_match(struct test_node *tn, net_addr *query, net_addr *data)
{ 
    return (tn->pos < PREFIXES_NUM) && net_equal(query, &data[tn->pos]); 
}


static int
t_match_random_net(const uint8_t *Data, size_t Size)
{
  bt_bird_init();
  bt_config_parse(BT_CONFIG_SIMPLE);


  int type = NET_IP4;

  pool *p = rp_new(&root_pool, "FIB pool");
  net_addr *nets = bt_random_nets_from_data(type, Size / 5, Data, Size);

  /* Make FIB structure */
  struct fib f;
  fib_init(&f, &root_pool, type, sizeof(struct test_node), OFFSETOF(struct test_node, n), 4, NULL);

  for (int i = 0; i < Size / 5; i++)
  {
    struct test_node *tn = fib_get(&f, &nets[i]);
    bt_assert(!tn->pos || net_match(tn, &nets[i], nets));
    tn->pos = i;
  }

//тест негативных матчей вынести в отедльный тест
    /* Test (mostly) negative matches */
    // for (int i = 0; i < PREFIX_TESTS_NUM; i++)
    // {
    //   net_addr net;
    //   bt_random_net(&net, type);

    //   struct test_node *tn = fib_find(&f, &net);
    //   bt_assert(!tn || net_match(tn, &net, nets));
    // }

    /* Test positive matches */
  for (int j = 0; j < Size / 5; j++)
  {
    struct test_node *tn = fib_find(&f, &nets[j]);
    bt_assert(tn && net_match(tn, &nets[j], nets));
  }

  rfree(p);
  tmp_flush();


  bt_bird_cleanup();
  return 1;
}
