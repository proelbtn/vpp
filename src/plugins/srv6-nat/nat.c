/*
 *------------------------------------------------------------------
 * nat.c - Network Address Translation for ICTSC
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <srv6-nat/nat.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

unsigned char srv6_nat_name[32] = "SRv6-NAT-plugin";
unsigned char keyword_str[32] = "NAT";
unsigned char def_str[64] = "Network Address Translation for ICTSC";
unsigned char params_str[64] = "from <ip4_address> to <ip4_address>";

srv6_nat_main_t srv6_nat_main;

/*****************************************/
/* SRv6 LocalSID instantiation and removal functions */

static int srv6_nat_creation_fn (ip6_sr_localsid_t *localsid) {
	return 0;
}

static int srv6_nat_removal_fn (ip6_sr_localsid_t *localsid) {
	clib_mem_free(localsid->plugin_mem);
	return 0;
}

/**********************************/
/* SRv6 LocalSID format functions */

u8 *format_srv6_nat (u8 *s, va_list *args) {
	srv6_nat_per_sid_memory_t *ls_mem = va_arg (*args, void *);

	s = format(s, "From: %U\n", format_ip4_address, &ls_mem->from);
	s = format(s, "\tTo: %U\n", format_ip4_address, &ls_mem->to);
	return format(s, "\tMask: %U", format_ip4_address, &ls_mem->mask);
}

uword unformat_srv6_nat (unformat_input_t *input, va_list *args) {
	void **plugin_mem = va_arg (*args, void **);
	srv6_nat_per_sid_memory_t *ls_mem;
	ip4_address_t from, to;

	if (!unformat (input, "end.nat")) return 0;

	if (!unformat (input, "from %U", unformat_ip4_address, &from))
		return 0;

	if (!unformat (input, "to %U", unformat_ip4_address, &to))
		return 0;

	/* Allocate per sid memory structure */
	ls_mem = clib_mem_alloc_aligned_at_offset(sizeof(srv6_nat_per_sid_memory_t), 0, 0, 1);

	/* Set to zero the memory */
	clib_memset (ls_mem, 0, sizeof(srv6_nat_per_sid_memory_t));

	ls_mem->mask.as_u32 = htonl(0xFFFFFFFF << 16);
	ls_mem->from.as_u32 = from.as_u32 & ls_mem->mask.as_u32;
	ls_mem->to.as_u32 = to.as_u32 & ls_mem->mask.as_u32;

	/* assign ls_mem to plugin_mem */
	*plugin_mem = ls_mem;

	return 1;
}

/*************************/
/* SRv6 LocalSID FIB DPO */

static u8 *format_srv6_nat_dpo (u8 * s, va_list * args) {
	index_t index = va_arg (*args, index_t);
	CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

	return (format (s, "SR: localsid_index:[%u]", index));
}

void srv6_nat_dpo_lock (dpo_id_t * dpo) {
}

void srv6_nat_dpo_unlock (dpo_id_t * dpo) {
}

const static dpo_vft_t srv6_nat_vft = {
	.dv_lock = srv6_nat_dpo_lock,
	.dv_unlock = srv6_nat_dpo_unlock,
	.dv_format = format_srv6_nat_dpo,
};

const static char *const srv6_nat_ip6_nodes[] = {
	"srv6-nat-rewrite",
	NULL,
};

const static char *const *const srv6_nat_nodes[DPO_PROTO_NUM] = {
	[DPO_PROTO_IP6] = srv6_nat_ip6_nodes,
};

/**********************/

static clib_error_t *srv6_nat_init (vlib_main_t *vm) {
	srv6_nat_main_t *sm = &srv6_nat_main;
	int rv = 0;
	/* Create DPO */
	sm->srv6_nat_dpo_type = dpo_register_new_type (
			&srv6_nat_vft, srv6_nat_nodes);

	/* Register SRv6 LocalSID */
	rv = sr_localsid_register_function (vm,
			srv6_nat_name,
			keyword_str,
			def_str,
			params_str,
			&sm->srv6_nat_dpo_type,
			format_srv6_nat,
			unformat_srv6_nat,
			srv6_nat_creation_fn,
			srv6_nat_removal_fn);
	if (rv < 0)
		clib_error_return (0, "SRv6 NAT LocalSID function could not be registered.");
	else
		sm->srv6_nat_behavior_id = rv;

	return 0;
}

VLIB_INIT_FUNCTION (srv6_nat_init);

VLIB_PLUGIN_REGISTER () = {
	.version = "1.0",
	.description = "Network Address Translatoin for ICTSC"
};
