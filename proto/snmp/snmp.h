/*
 *	BIRD -- Simple Network Management Protocol (SNMP)
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SNMP_H_
#define _BIRD_SNMP_H_

#include "nest/bird.h"
#include "nest/protocol.h"
#include "lib/resource.h"
#include "lib/ip.h"
#include "lib/socket.h"
#include "lib/timer.h"
#include "filter/data.h"

#define SNMP_UNDEFINED	0
#define SNMP_BGP	1
#define SNMP_OSPF	2
#define SNMP_INVALID  255

#define SNMP_PORT 705

#define SNMP_RX_BUFFER_SIZE 8192
#define SNMP_TX_BUFFER_SIZE 8192
#define SNMP_PKT_SIZE_MAX 4098

#define AGENTX_MASTER_ADDR "/var/agentx/master"

enum snmp_proto_state {
  SNMP_DOWN = 0,
  SNMP_INIT = 1,
  SNMP_LOCKED,
  SNMP_OPEN,
  SNMP_REGISTER,
  SNMP_CONN,
  SNMP_STOP,
};

struct snmp_bond {
  node n;
  struct proto_config *config;
  u8 type;
};

enum snmp_transport_type {
  SNMP_TRANS_DEFAULT,
  SNMP_TRANS_UNIX,
  SNMP_TRANS_TCP,
};

struct snmp_config {
  struct proto_config cf;
  enum snmp_transport_type trans_type;
  ip4_addr local_ip;
  u16 local_port;
  ip_addr remote_ip;		  /* master agentx IP address for TCP transport */
  u16 remote_port;
  const char *remote_path;	  /* master agentx UNIX socket name */

  ip4_addr bgp_local_id;	  /* BGP4-MIB related fields */
  u32 bgp_local_as;

  btime timeout;
  btime startup_delay;
  u8 priority;
  u32 bonds;
  const char *description;	  /* The order of fields is not arbitrary */
  list bgp_entries;		  /* We want dynamically allocated fields to be
				   * at the end of the config struct.
				   * We use this fact to check differences of
				   * nonallocated parts of configs with memcpy
				   */
  //const struct oid *oid_identifier;	TODO
};

#define SNMP_BGP_P_REGISTERING	0x01
#define SNMP_BGP_P_REGISTERED	0x02

struct snmp_bgp_peer {
  const struct bgp_proto *bgp_proto;
  ip4_addr peer_ip;		      /* used as hash key */
  struct snmp_bgp_peer *next;
};

struct snmp_registered_oid {
  node n;
  struct oid *oid;
};


struct snmp_proto {
  struct proto p;
  struct object_lock *lock;
  pool *pool;			  /* a shortcut to the procotol mem. pool */
  linpool *lp;			  /* linpool for bgp_trie nodes */
  linpool *end_oids;

  enum snmp_proto_state state;

  ip4_addr local_ip;
  ip_addr remote_ip;
  u16 local_port;
  u16 remote_port;

  ip4_addr bgp_local_id;		  /* BGP4-MIB related fields */
  u32 bgp_local_as;

  sock *sock;


  btime timeout;		  /* timeout is part of MIB registration. It
				    specifies how long should the master
				    agent wait for request responses. */

  u32 session_id;
  u32 transaction_id;
  u32 packet_id;

  uint registrations_to_ack;		    /* counter of pending responses to register-pdu */
  list registration_queue;		    /* list containing snmp_register records */

  // map
  struct f_trie *bgp_trie;
  HASH(struct snmp_bgp_peer) bgp_hash;
  struct tbf rl_gen;

  list pending_pdus;

  timer *ping_timer;
  btime startup_delay;
  timer *startup_timer;

  struct mib_tree *mib_tree;
};

enum agentx_mibs {
  BGP4_MIB_ID,
  AGENTX_MIB_COUNT,
  AGENTX_MIB_UNKNOWN,
};

extern const struct oid *agentx_available_mibs[AGENTX_MIB_COUNT + 1];
void agentx_get_mib_init(pool *p);
enum agentx_mibs agentx_get_mib(const struct oid *o);

struct snmp_registration;
struct agentx_response; /* declared in subagent.h */
typedef void (*snmp_reg_hook_t)(struct snmp_proto *p, const struct agentx_response *res, struct snmp_registration *reg);

struct snmp_registration {
  node n;
  enum agentx_mibs mib;
  u32 session_id;
  u32 transaction_id;
  u32 packet_id;
  struct oid *oid;
  snmp_reg_hook_t reg_hook_ok; /* hook called when successful response to OID registration is recieved */
  snmp_reg_hook_t reg_hook_fail; /* hook called when OID registration fail */
};

void snmp_startup(struct snmp_proto *p);
void snmp_connected(sock *sk);
void snmp_startup_timeout(timer *tm);
void snmp_reconnect(timer *tm);
int snmp_set_state(struct snmp_proto *p, enum snmp_proto_state state);

int snmp_reset(struct snmp_proto *p);
void snmp_up(struct snmp_proto *p);

extern const char agentx_master_addr[sizeof(AGENTX_MASTER_ADDR)];

static inline int
proto_is_snmp(const struct proto *P)
{
  extern struct protocol proto_snmp;
  return P->proto == &proto_snmp;
}


#endif