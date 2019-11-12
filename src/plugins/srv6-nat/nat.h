#ifndef __included_nat_h__
#define __included_nat_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/srv6/sr.h>
#include <vnet/srv6/sr_packet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

typedef struct {
    /* API message ID base */
    u16 msg_id_base;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;

    /* DPO type */
    dpo_type_t srv6_nat_dpo_type;

    /* SRv6 LocalSID behavior number */
    u32 srv6_nat_behavior_id;
} srv6_nat_main_t;

/*
 * This is the memory that will be stored per each localsid
 * the user instantiates
 */
typedef struct {
	ip4_address_t from;
	ip4_address_t to;
	ip4_address_t mask;
} srv6_nat_per_sid_memory_t ;

extern srv6_nat_main_t srv6_nat_main;

format_function_t format_srv6_localsid;
unformat_function_t unformat_srv6_localsid;

void srv6_nat_dpo_lock (dpo_id_t *dpo);
void srv6_nat_dpo_unlock (dpo_id_t *dpo);

extern vlib_node_registration_t srv6_nat_node;

#endif /* __included_sample_h__ */
