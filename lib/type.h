/*
 *     BIRD Internet Routing Daemon -- Internal Data Types
 *
 *     (c) 2022 Maria Matejka <mq@jmq.cz>
 *
 *     Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_TYPE_H_
#define _BIRD_TYPE_H_

#include "lib/birdlib.h"
#include "lib/attrs.h"

union bval {
#define BVAL_ITEMS									\
  struct {										\
    u32 data;			/* Integer type inherited from eattrs */		\
    PADDING(data, 0, 4);	/* Must be padded on 64-bits */				\
  };											\
  struct {										\
    u32 i;			/* Integer type inherited from filters */		\
    PADDING(i, 0, 4);		/* Must be padded on 64-bits */				\
  };											\
  const struct adata *ptr;	/* Generic attribute data inherited from eattrs */	\
  const struct adata *ad;     	/* Generic attribute data inherited from filters */	\

  BVAL_ITEMS;
};

union bval_long {
  union bval bval;		/* For direct assignments */
  BVAL_ITEMS;			/* For item-wise access */

  u64 ec;
  lcomm lc;
  ip_addr ip;
  const net_addr *net;
  const char *s;
  const struct f_tree *t;
  const struct f_trie *ti;
  const struct f_path_mask *path_mask;
  struct f_path_mask_item pmi;
};


/* Internal types */
enum btype {
/* Nothing. Simply nothing. */
  T_VOID = 0,

/* Something but inaccessible. */
  T_OPAQUE = 0x02,		/* Opaque byte string (not filterable) */
  T_IFACE = 0x0c,		/* Pointer to an interface (inside adata) */

/* Types shared with eattrs */
  T_INT = 0x01,			/* 32-bit unsigned integer number */
  T_IP = 0x04,			/* IP address */
  T_QUAD = 0x05,		/* Router ID (IPv4 address) */
  T_PATH = 0x06,		/* BGP AS path (encoding per RFC 1771:4.3) */
  T_CLIST = 0x0a,		/* Set of u32's (e.g., a community list) */
  T_ECLIST = 0x0e,		/* Set of pairs of u32's - ext. community list */
  T_LCLIST = 0x08,		/* Set of triplets of u32's - large community list */

  T_ENUM_BGP_ORIGIN = 0x11,	/* BGP Origin enum */
  T_ENUM_RA_PREFERENCE = 0x13,	/* RA Preference enum */

#define EAF_TYPE__MAX 0x1f
#define EAF_EMBEDDED 0x01		/* Data stored in eattr.u.data (part of type spec) */
					/* Otherwise, attribute data is adata */

/* Other user visible types which fit in int */
  T_BOOL = 0xa0,
  T_PAIR = 0xa4,  /*	Notice that pair is stored as integer: first << 16 | second */

/* Put enumerational types in 0x20..0x3f range */
  T_ENUM_LO = 0x10,
  T_ENUM_HI = 0x3f,

  T_ENUM_RTS = 0x31,
  T_ENUM_SCOPE = 0x33,
  T_ENUM_RTC = 0x35,
  T_ENUM_RTD = 0x37,
  T_ENUM_ROA = 0x39,
  T_ENUM_NETTYPE = 0x3b,
  T_ENUM_AF = 0x3d,

/* new enums go here */

#define T_ENUM T_ENUM_LO ... T_ENUM_HI

/* Bigger ones */
  T_NET = 0xb0,
  T_STRING = 0xb4,
  T_PATH_MASK = 0xb8,	/* mask for BGP path */
  T_EC = 0xbc,		/* Extended community value, u64 */
  T_LC = 0xc0,		/* Large community value, lcomm */
  T_RD = 0xc4,		/* Route distinguisher for VPN addresses */
  T_PATH_MASK_ITEM = 0xc8,	/* Path mask item for path mask constructors */

  T_SET = 0x80,
  T_PREFIX_SET = 0x84,
} PACKED;

typedef enum btype btype;

STATIC_ASSERT(sizeof(btype) == sizeof(byte));


#endif