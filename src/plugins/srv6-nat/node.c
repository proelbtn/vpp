#include <vat/vat.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <srv6-nat/nat.h>

typedef struct {
	u32 localsid_index;
} srv6_nat_trace_t;

static u8 *format_srv6_nat_trace (u8 *s, va_list *args)
{
	CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
	CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
	srv6_nat_trace_t *t = va_arg (*args, srv6_nat_trace_t *);
	s = format (s, "srv6-nat-rewrite: localsid_index %d\n",
			t->localsid_index);
	return s;
}

vlib_node_registration_t srv6_nat_node;

#define foreach_srv6_nat_counter \
	_(PROCESSED, "srv6-nat-rewrite processed packets") \
_(NO_SRH, "(Error) No SRH.")

typedef enum {
#define _(sym,str) SRV6_NAT_COUNTER_##sym,
	foreach_srv6_nat_counter
#undef _
		SRV6_NAT_N_COUNTERS,
} srv6_nat_counters;

static char * srv6_nat_counter_strings[] = {
#define _(sym,string) string,
	foreach_srv6_nat_counter
#undef _
};

typedef enum {
	SRV6_NAT_NEXT_ERROR,
	SRV6_NAT_NEXT_IP6LOOKUP,
	SRV6_NAT_N_NEXT,
} srv6_nat_next_t;


static_always_inline void rewrite_inner_header(ip4_header_t *ip0,
		ip6_sr_localsid_t *ls0,
		u32 *next0) {
	u32 check_diff = 0;
	u32 check;
	srv6_nat_per_sid_memory_t *ls0_mem = ls0->plugin_mem;
	tcp_header_t *tcp0;
	udp_header_t *udp0;

	if ((ip0->src_address.as_u32 & ls0_mem->mask.as_u32) == ls0_mem->from.as_u32) {
		u16 *data = (void *)&ip0->src_address;

		check_diff += (~data[0]) & 0xffff;
		check_diff += (~data[1]) & 0xffff;

		ip0->src_address.as_u32 &= ~(ls0_mem->mask.as_u32);
		ip0->src_address.as_u32 |= ls0_mem->to.as_u32;

		check_diff += data[0];
		check_diff += data[1];
	}
	else if ((ip0->dst_address.as_u32 & ls0_mem->mask.as_u32) == ls0_mem->to.as_u32) {
		u16 *data = (void *)&ip0->dst_address;

		check_diff += (~data[0]) & 0xffff;
		check_diff += (~data[1]) & 0xffff;

		ip0->dst_address.as_u32 &= ~(ls0_mem->mask.as_u32);
		ip0->dst_address.as_u32 |= ls0_mem->from.as_u32;

		check_diff += data[0];
		check_diff += data[1];
	}
	else {
		*next0 = SRV6_NAT_NEXT_ERROR;
		return;
	}

	check = (~ip0->checksum) & 0xffff;
	check += check_diff;
	for (int i = 0; i < 4; i++) check = (check & 0xffff) + (check >> 16);
	ip0->checksum = ~check;

	switch (ip0->protocol) {
		case IP_PROTOCOL_TCP:
			tcp0 = (tcp_header_t *)(ip0 + 1);

			check = (~tcp0->checksum) & 0xffff;
			check += check_diff;
			for (int i = 0; i < 4; i++) check = (check & 0xffff) + (check >> 16);
			tcp0->checksum = ~check;

			break;
		case IP_PROTOCOL_UDP:
			udp0 = (udp_header_t *)(ip0 + 1);

			check = (~udp0->checksum) & 0xffff;
			check += check_diff;
			for (int i = 0; i < 4; i++) check = (check & 0xffff) + (check >> 16);
			udp0->checksum = ~check;

			break;
	}

	*next0 = SRV6_NAT_NEXT_IP6LOOKUP;
}


static_always_inline void end_nat_processing (vlib_node_runtime_t *node,
		vlib_buffer_t *b0,
		ip6_header_t *ip0,
		ip6_sr_header_t *sr0,
		ip6_sr_localsid_t *ls0,
		u32 *next0) {
	*next0 = SRV6_NAT_NEXT_ERROR;

	/* 1. validate this packet is correct */
	if (sr0->protocol != IP_PROTOCOL_IP_IN_IP) return;
	if (sr0->segments_left == 0) return;

	/* 2. rewrite inner IPv4 header */
	ip4_header_t *ip0_in = (ip4_header_t *)((u8*)sr0 + 8 * (sr0->length + 1));
	rewrite_inner_header(ip0_in, ls0, next0);

	/* 3. update next destination of packet */
	sr0->segments_left--;
	ip0->dst_address = sr0->segments[sr0->segments_left];
}

static uword srv6_nat_fn(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
	u32 n_left_from, *from, *to_next;
	u32 next_index;
	u32 pkts_swapped = 0;

	ip6_sr_main_t *sm = &sr_main;

	from = vlib_frame_vector_args(frame);
	n_left_from = frame->n_vectors;
	next_index = node->cached_next_index;
	u32 thread_index = vlib_get_thread_index();

	while (n_left_from > 0)
	{
		u32 n_left_to_next;

		vlib_get_next_frame (vm, node, next_index,
				to_next, n_left_to_next);

		while (n_left_from > 0 && n_left_to_next > 0)
		{
			u32 bi0;
			vlib_buffer_t * b0;
			ip6_header_t * ip0 = 0;
			ip6_sr_header_t * sr0;
			ip6_ext_header_t *prev0;
			u32 next0 = SRV6_NAT_NEXT_IP6LOOKUP;
			ip6_sr_localsid_t *ls0;

			bi0 = from[0];
			to_next[0] = bi0;
			from += 1;
			to_next += 1;
			n_left_from -= 1;
			n_left_to_next -= 1;

			b0 = vlib_get_buffer (vm, bi0);
			ip0 = vlib_buffer_get_current (b0);
			sr0 = (ip6_sr_header_t *)(ip0+1);

			/* Lookup the SR End behavior based on IP DA (adj) */
			ls0 = pool_elt_at_index(sm->localsids, vnet_buffer(b0)->ip.adj_index[VLIB_TX]);

			/* SRH processing */
			ip6_ext_header_find_t (ip0, prev0, sr0, IP_PROTOCOL_IPV6_ROUTE);
			end_nat_processing (node, b0, ip0, sr0, ls0, &next0);

			if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
			{
				srv6_nat_trace_t *tr = vlib_add_trace(vm, node, b0, sizeof(*tr));
				tr->localsid_index = ls0 - sm->localsids;
			}

			/* This increments the SRv6 per LocalSID counters.*/
			vlib_increment_combined_counter
				(((next0 == SRV6_NAT_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) : &(sm->sr_ls_valid_counters)),
				 thread_index,
				 ls0 - sm->localsids,
				 1, vlib_buffer_length_in_chain (vm, b0));

			vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					n_left_to_next, bi0, next0);

			pkts_swapped++;
		}
		vlib_put_next_frame (vm, node, next_index, n_left_to_next);

	}

	return frame->n_vectors;
}

VLIB_REGISTER_NODE (srv6_nat_node) = {
	.function = srv6_nat_fn,
	.name = "srv6-nat-rewrite",
	.vector_size = sizeof (u32),
	.format_trace = format_srv6_nat_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_errors = SRV6_NAT_N_COUNTERS,
	.error_strings = srv6_nat_counter_strings,
	.n_next_nodes = SRV6_NAT_N_NEXT,
	.next_nodes = {
		[SRV6_NAT_NEXT_IP6LOOKUP] = "ip6-lookup",
		[SRV6_NAT_NEXT_ERROR] = "error-drop",
	},
};
