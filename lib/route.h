/*
 *	BIRD Internet Routing Daemon -- Routing data structures
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2022 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LIB_ROUTE_H_
#define _BIRD_LIB_ROUTE_H_

#include "lib/type.h"

struct network;
struct proto;
struct cli;


typedef struct rte {
  struct rta *attrs;			/* Attributes of this route */
  const net_addr *net;			/* Network this RTE belongs to */
  struct rte_src *src;			/* Route source that created the route */
  struct rt_import_hook *sender;	/* Import hook used to send the route to the routing table */
  btime lastmod;			/* Last modified (set by table) */
  u32 id;				/* Table specific route id */
  byte flags;				/* Table-specific flags */
  byte pflags;				/* Protocol-specific flags */
  u8 generation;			/* If this route import is based on other previously exported route,
					   this value should be 1 + MAX(generation of the parent routes).
					   Otherwise the route is independent and this value is zero. */
} rte;

#define REF_FILTERED	2		/* Route is rejected by import filter */
#define REF_STALE	4		/* Route is stale in a refresh cycle */
#define REF_DISCARD	8		/* Route is scheduled for discard */
#define REF_MODIFY	16		/* Route is scheduled for modify */

/* Route is valid for propagation (may depend on other flags in the future), accepts NULL */
static inline int rte_is_valid(rte *r) { return r && !(r->flags & REF_FILTERED); }

/* Route just has REF_FILTERED flag */
static inline int rte_is_filtered(rte *r) { return !!(r->flags & REF_FILTERED); }

struct rte_src {
  struct rte_src *next;			/* Hash chain */
  struct proto *proto;			/* Protocol the source is based on */
  u32 private_id;			/* Private ID, assigned by the protocol */
  u32 global_id;			/* Globally unique ID of the source */
  unsigned uc;				/* Use count */
};


struct rte_src *rt_find_source(struct proto *p, u32 id);
struct rte_src *rt_get_source(struct proto *p, u32 id);
static inline void rt_lock_source(struct rte_src *src) { src->uc++; }
static inline void rt_unlock_source(struct rte_src *src) { src->uc--; }
void rt_prune_sources(void);

/*
 *	Route Attributes
 *
 *	Beware: All standard BGP attributes must be represented here instead
 *	of making them local to the route. This is needed to ensure proper
 *	construction of BGP route attribute lists.
 */

/* Nexthop structure */
struct nexthop {
  ip_addr gw;				/* Next hop */
  struct iface *iface;			/* Outgoing interface */
  struct nexthop *next;
  byte flags;
  byte weight;
  byte labels_orig;			/* Number of labels before hostentry was applied */
  byte labels;				/* Number of all labels */
  u32 label[0];
};

#define RNF_ONLINK		0x1	/* Gateway is onlink regardless of IP ranges */


typedef struct rta {
  struct rta *next, **pprev;		/* Hash chain */
  u32 uc;				/* Use count */
  u32 hash_key;				/* Hash over important fields */
  struct ea_list *eattrs;		/* Extended Attribute chain */
  struct hostentry *hostentry;		/* Hostentry for recursive next-hops */
  ip_addr from;				/* Advertising router */
  u32 igp_metric;			/* IGP metric to next hop (for iBGP routes) */
  u16 cached:1;				/* Are attributes cached? */
  u16 source:7;				/* Route source (RTS_...) */
  u16 scope:4;				/* Route scope (SCOPE_... -- see ip.h) */
  u16 dest:4;				/* Route destination type (RTD_...) */
  word pref;
  struct nexthop nh;			/* Next hop */
} rta;

#define RTS_STATIC 1			/* Normal static route */
#define RTS_INHERIT 2			/* Route inherited from kernel */
#define RTS_DEVICE 3			/* Device route */
#define RTS_STATIC_DEVICE 4		/* Static device route */
#define RTS_REDIRECT 5			/* Learned via redirect */
#define RTS_RIP 6			/* RIP route */
#define RTS_OSPF 7			/* OSPF route */
#define RTS_OSPF_IA 8			/* OSPF inter-area route */
#define RTS_OSPF_EXT1 9			/* OSPF external route type 1 */
#define RTS_OSPF_EXT2 10		/* OSPF external route type 2 */
#define RTS_BGP 11			/* BGP route */
#define RTS_PIPE 12			/* Inter-table wormhole */
#define RTS_BABEL 13			/* Babel route */
#define RTS_RPKI 14			/* Route Origin Authorization */
#define RTS_PERF 15			/* Perf checker */
#define RTS_MAX 16

#define RTD_NONE 0			/* Undefined next hop */
#define RTD_UNICAST 1			/* Next hop is neighbor router */
#define RTD_BLACKHOLE 2			/* Silently drop packets */
#define RTD_UNREACHABLE 3		/* Reject as unreachable */
#define RTD_PROHIBIT 4			/* Administratively prohibited */
#define RTD_MAX 5

#define IGP_METRIC_UNKNOWN 0x80000000	/* Default igp_metric used when no other
					   protocol-specific metric is availabe */


extern const char * rta_dest_names[RTD_MAX];

static inline const char *rta_dest_name(uint n)
{ return (n < RTD_MAX) ? rta_dest_names[n] : "???"; }

/* Route has regular, reachable nexthop (i.e. not RTD_UNREACHABLE and like) */
static inline int rte_is_reachable(rte *r)
{ return r->attrs->dest == RTD_UNICAST; }


/*
 *	Extended Route Attributes
 */

typedef struct eattr {
  word id;				/* EA_CODE(PROTOCOL_..., protocol-dependent ID) */
  byte flags;				/* Protocol-dependent flags */
  byte type:5;				/* Attribute type */
  byte originated:1;			/* The attribute has originated locally */
  byte fresh:1;				/* An uncached attribute (e.g. modified in export filter) */
  byte undef:1;				/* Explicitly undefined */

  PADDING(unused, 0, 4);

  union bval u;
} eattr;


#define EA_CODE(proto,id) (((proto) << 8) | (id))
#define EA_ID(ea) ((ea) & 0xff)
#define EA_PROTO(ea) ((ea) >> 8)
#define EA_CUSTOM(id) ((id) | EA_CUSTOM_BIT)
#define EA_IS_CUSTOM(ea) ((ea) & EA_CUSTOM_BIT)
#define EA_CUSTOM_ID(ea) ((ea) & ~EA_CUSTOM_BIT)

const char *ea_custom_name(uint ea);

#define EA_GEN_IGP_METRIC EA_CODE(PROTOCOL_NONE, 0)

#define EA_CODE_MASK 0xffff
#define EA_CUSTOM_BIT 0x8000
#define EA_ALLOW_UNDEF 0x10000		/* ea_find: allow EAF_TYPE_UNDEF */
#define EA_BIT(n) ((n) << 24)		/* Used in bitfield accessors */
#define EA_BIT_GET(ea) ((ea) >> 24)

typedef struct ea_list {
  struct ea_list *next;			/* In case we have an override list */
  byte flags;				/* Flags: EALF_... */
  byte rfu;
  word count;				/* Number of attributes */
  eattr attrs[0];			/* Attribute definitions themselves */
} ea_list;

#define EALF_SORTED 1			/* Attributes are sorted by code */
#define EALF_BISECT 2			/* Use interval bisection for searching */
#define EALF_CACHED 4			/* Attributes belonging to cached rta */

struct ea_walk_state {
  ea_list *eattrs;			/* Ccurrent ea_list, initially set by caller */
  eattr *ea;				/* Current eattr, initially NULL */
  u32 visited[4];			/* Bitfield, limiting max to 128 */
};

eattr *ea_find(ea_list *, unsigned ea);
eattr *ea_walk(struct ea_walk_state *s, uint id, uint max);

/**
 * ea_get_int - fetch an integer attribute
 * @e: attribute list
 * @id: attribute ID
 * @def: default value
 *
 * This function is a shortcut for retrieving a value of an integer attribute
 * by calling ea_find() to find the attribute, extracting its value or returning
 * a provided default if no such attribute is present.
 */
static inline u32
ea_get_int(ea_list *e, unsigned id, u32 def)
{
  eattr *a = ea_find(e, id);
  return a ? a->u.data : def;
}

void ea_dump(ea_list *);
int ea_same(ea_list *x, ea_list *y);	/* Test whether two ea_lists are identical */
uint ea_hash(ea_list *e);	/* Calculate 16-bit hash value */
ea_list *ea_append(ea_list *to, ea_list *what);
void ea_format_bitfield(const struct eattr *a, byte *buf, int bufsize, const char **names, int min, int max);

/* Normalize ea_list; allocates the result from tmp_linpool */
ea_list *ea_normalize(const ea_list *e);

uint ea_list_size(ea_list *);
void ea_list_copy(ea_list *dest, ea_list *src, uint size);

struct ea_one_attr_list {
  ea_list l;
  eattr a;
};

#define EA_LITERAL_EMBEDDED(_id, _type, _flags, _val) ({ \
    ASSERT_DIE(_type & EAF_EMBEDDED); \
    EA_LITERAL_GENERIC(_id, _type, _flags, .u.i = _val); \
    })

#define EA_LITERAL_STORE_ADATA(_id, _type, _flags, _buf, _len) ({ \
    ASSERT_DIE(!(_type & EAF_EMBEDDED)); \
    EA_LITERAL_GENERIC(_id, _type, _flags, .u.ad = tmp_store_adata((_buf), (_len))); \
    })

#define EA_LITERAL_DIRECT_ADATA(_id, _type, _flags, _adata) ({ \
    ASSERT_DIE(!(_type & EAF_EMBEDDED)); \
    EA_LITERAL_GENERIC(_id, _type, _flags, .u.ad = _adata); \
    })

#define EA_LITERAL_GENERIC(_id, _type, _flags, ...) \
  ((eattr) { .id = _id, .type = _type, .flags = _flags, __VA_ARGS__ })

static inline eattr *
ea_set_attr(ea_list **to, eattr a)
{
  struct ea_one_attr_list *ea = tmp_alloc(sizeof(*ea));
  *ea = (struct ea_one_attr_list) {
    .l.flags = EALF_SORTED,
    .l.count = 1,
    .l.next = *to,
    .a = a,
  };

  *to = &ea->l;
  return &ea->a;
}

static inline void
ea_unset_attr(ea_list **to, _Bool local, uint code)
{
  ea_set_attr(to, EA_LITERAL_GENERIC(code, 0, 0,
	.fresh = local, .originated = local, .undef = 1));
}

static inline void
ea_set_attr_u32(ea_list **to, uint id, uint flags, uint type, u32 data)
{ ea_set_attr(to, EA_LITERAL_EMBEDDED(id, type, flags, data)); }

static inline void
ea_set_attr_data(ea_list **to, uint id, uint flags, uint type, void *data, uint len)
{ ea_set_attr(to, EA_LITERAL_STORE_ADATA(id, type, flags, data, len)); }


#define NEXTHOP_MAX_SIZE (sizeof(struct nexthop) + sizeof(u32)*MPLS_MAX_LABEL_STACK)

static inline size_t nexthop_size(const struct nexthop *nh)
{ return sizeof(struct nexthop) + sizeof(u32)*nh->labels; }
int nexthop__same(struct nexthop *x, struct nexthop *y); /* Compare multipath nexthops */
static inline int nexthop_same(struct nexthop *x, struct nexthop *y)
{ return (x == y) || nexthop__same(x, y); }
struct nexthop *nexthop_merge(struct nexthop *x, struct nexthop *y, int rx, int ry, int max, linpool *lp);
struct nexthop *nexthop_sort(struct nexthop *x);
static inline void nexthop_link(struct rta *a, struct nexthop *from)
{ memcpy(&a->nh, from, nexthop_size(from)); }
void nexthop_insert(struct nexthop **n, struct nexthop *y);
int nexthop_is_sorted(struct nexthop *x);

void rta_init(void);
static inline size_t rta_size(const rta *a) { return sizeof(rta) + sizeof(u32)*a->nh.labels; }
#define RTA_MAX_SIZE (sizeof(rta) + sizeof(u32)*MPLS_MAX_LABEL_STACK)
rta *rta_lookup(rta *);			/* Get rta equivalent to this one, uc++ */
static inline int rta_is_cached(rta *r) { return r->cached; }
static inline rta *rta_clone(rta *r) { r->uc++; return r; }
void rta__free(rta *r);
static inline void rta_free(rta *r) { if (r && !--r->uc) rta__free(r); }
rta *rta_do_cow(rta *o, linpool *lp);
static inline rta * rta_cow(rta *r, linpool *lp) { return rta_is_cached(r) ? rta_do_cow(r, lp) : r; }
void rta_dump(rta *);
void rta_dump_all(void);
void rta_show(struct cli *, rta *);

u32 rt_get_igp_metric(rte *rt);

#endif