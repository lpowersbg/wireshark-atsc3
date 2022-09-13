/* packet-atsc3-stltp.c
 * ATSC 3.0
 * STLTP dissector
 * Copyright 2022, Jason Justman <jjustman@ngbp.org>
 *
 * Based off of A/324:2022
 *
 * References:
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/conversation.h>

#include "tvbuff.h"
#include "tvbuff-int.h"
#include "packet-atsc3-common.h"


#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>
#include <epan/reassemble.h>

//hack

#include "packet-ip.h"
/* Initialize the protocol and registered fields */
/* ============================================= */

void proto_register_atsc3_stltp(void);
void proto_reg_handoff_atsc3_stltp(void);

static int proto_atsc3_stltp = -1;
static dissector_handle_t ip_handle;


static int hf_payload = -1;
static int hf_payload_str = -1;

static int ett_main = -1;

static expert_field ei_payload_decompress_failed = EI_INIT;


static reassembly_table stltp_ctp_outer_reassembly_table;
static reassembly_table stltp_ctp_inner_reassembly_table;

//stltp rtp outer
static int hf_ctp_outer_fixed_header_version = -1;
static int hf_ctp_outer_fixed_header_padding = -1;
static int hf_ctp_outer_fixed_header_extension = -1;
static int hf_ctp_outer_fixed_header_csrc_count = -1;
static int hf_ctp_outer_fixed_header_marker = -1;
static guint32 ctp_outer_fixed_header_marker = 0;

static int 	hf_ctp_outer_fixed_header_payload_type = -1;
static guint32 ctp_outer_fixed_header_payload_type = 0;

static int hf_ctp_outer_fixed_header_sequence_number = -1;
static guint32 ctp_outer_fixed_header_sequence_number = 0;

//ctp_outer_fixed_header_payload_type == ATSC3_STLTP_ctp_outer_PAYLOAD_TYPE_DSTP || ctp_outer_fixed_header_payload_type == ATSC3_STLTP_ctp_outer_PAYLOAD_TYPE_ALPTP
static int hf_ctp_outer_fixed_header_timestamp_min_seconds = -1;
static int hf_ctp_outer_fixed_header_timestamp_min_fraction = -1;

// ctp_outer_fixed_header_payload_type == ATSC3_STLTP_ctp_outer_PAYLOAD_TYPE_STLTP
static int hf_ctp_outer_fixed_header_timestamp_seconds_pre = -1;
static int hf_ctp_outer_fixed_header_timestamp_a_milliseconds_seconds_pre = -1;

//ctp_outer_fixed_header_payload_type == reserved
static int hf_ctp_outer_fixed_header_reserved_32b = -1;

static int hf_ctp_outer_fixed_header_protocol_version = -1;
static int hf_ctp_outer_fixed_header_redundancy = -1;
static int hf_ctp_outer_fixed_header_number_of_channels = -1;
static int hf_ctp_outer_fixed_header_reserved_10 = -1;
static int hf_ctp_outer_fixed_header_reserved_14 = -1;

static int hf_ctp_outer_fixed_header_packet_offset = -1;
static guint32 ctp_outer_fixed_header_packet_offset = 0;

static int hf_ip_version = -1;
static int hf_ip_hdr_len = -1;
static int hf_ip_len = -1;
static int hf_ip_proto = -1;
static int hf_ip_dst = -1;
static int hf_ip_src = -1;
static int hf_ctp_inner_udp_source_port = -1;
static int hf_ctp_inner_udp_dst_port = -1;

static int hf_ctp_inner_fixed_header_csrc_count;

static int 	hf_ctp_inner_fixed_header_payload_type = -1;
static guint32 ctp_inner_fixed_header_payload_type = 0;

static int hf_ctp_inner_fixed_header_marker = -1;
static guint32 ctp_inner_fixed_header_marker = 0;

static int hf_ctp_inner_fixed_header_timestamp_seconds_pre = -1;
static int hf_ctp_inner_fixed_header_timestamp_a_milliseconds_seconds_pre = -1;

static int  hf_ctp_inner_bbp_length = -1;
static guint32 ctp_inner_bbp_length = 0;


/*************************************************
 * Util fcns to display
 *   fragment_table & reassembled_table fd-chains
 ************************************************/
//
//static struct _fd_flags {
//    guint32 flag;
//    gchar  *flag_name;
//} fd_flags[] = {
//    {FD_DEFRAGMENTED         ,"DF"},
//    {FD_DATALEN_SET          ,"DS"},
//    {FD_SUBSET_TVB,          ,"ST"},
//    {FD_BLOCKSEQUENCE        ,"BS"},
//    {FD_PARTIAL_REASSEMBLY   ,"PR"},
//    {FD_OVERLAP              ,"OL"},
//    {FD_OVERLAPCONFLICT      ,"OC"},
//    {FD_MULTIPLETAILS        ,"MT"},
//    {FD_TOOLONGFRAGMENT      ,"TL"},
//};
//
//#define N_FD_FLAGS (signed)(sizeof(fd_flags)/sizeof(struct _fd_flags))
//
//static void
//print_fd(fragment_head *fd, gboolean is_head) {
//    int i;
//
//    g_assert(fd != NULL);
//    printf("        %08x %08x %3d %3d %3d", fd, fd->next, fd->frame, fd->offset, fd->len);
//    if (is_head) {
//        printf(" %3d %3d", fd->datalen, fd->reassembled_in);
//    } else {
//        printf( "        ");
//    }
//    printf(" 0x%08x", fd->data);
//    for (i=0; i<N_FD_FLAGS; i++) {
//        printf(" %s", (fd->flags & fd_flags[i].flag) ? fd_flags[i].flag_name : "  ");
//    }
//    printf("\n");
//}
//
//static void
//print_fd_chain(fragment_head *fd_head) {
//    fragment_item *fdp;
//
//    g_assert(fd_head != NULL);
//    print_fd(fd_head, TRUE);
//    for (fdp=fd_head->next; fdp != NULL; fdp=fdp->next) {
//        print_fd(fdp, FALSE);
//    }
//}
//
//static void
//print_fragment_table_chain(gpointer k, gpointer v, gpointer ud) {
//    fragment_key  *key     = (fragment_key*)k;
//    fragment_head *fd_head = (fragment_head *)v;
//    printf("  --> FT: %3d 0x%08x 0x%08x\n", key->id, *(guint32 *)(key->src.data), *(guint32 *)(key->dst.data));
//    print_fd_chain(fd_head);
//}
//
//static void
//print_fragment_table(void) {
//    printf("\n Fragment Table -------\n");
//    g_hash_table_foreach(fragment_table, print_fragment_table_chain, NULL);
//}
//
//static void
//print_reassembled_table_chain(gpointer k, gpointer v, gpointer ud) {
//    reassembled_key  *key  = (reassembled_key*)k;
//    fragment_head *fd_head = (fragment_head *)v;
//    printf("  --> RT: %5d %5d\n", key->id, key->frame);
//    print_fd_chain(fd_head);
//}
//
//static void
//print_reassembled_table(void) {
//    printf("\n Reassembled Table ----\n");
//    g_hash_table_foreach(test_reassembly_table.reassembled_table, print_reassembled_table_chain, NULL);
//}
//
//static void
//print_tables(void) {
//    print_fragment_table();
//    print_reassembled_table();
//}


static void
fragment_reset_defragmentation(fragment_head *fd_head)
{
	/* Caller must ensure that this function is only called when
	 * defragmentation is safe to undo. */
	//DISSECTOR_ASSERT(fd_head->flags & FD_DEFRAGMENTED);

	for (fragment_item *fd_i = fd_head->next; fd_i; fd_i = fd_i->next) {
		if (!fd_i->tvb_data) {
			fd_i->tvb_data = tvb_new_subset_remaining(fd_head->tvb_data, fd_i->offset);
			fd_i->flags |= FD_SUBSET_TVB;
		}
		fd_i->flags &= (~FD_TOOLONGFRAGMENT) & (~FD_MULTIPLETAILS);
	}
	fd_head->flags &= ~(FD_DEFRAGMENTED|FD_PARTIAL_REASSEMBLY|FD_DATALEN_SET);
	fd_head->flags &= ~(FD_TOOLONGFRAGMENT|FD_MULTIPLETAILS);
	fd_head->datalen = 0;
	fd_head->reassembled_in = 0;
	fd_head->reas_in_layer_num = 0;
}
static gint ett_tcp_segments = -1;
static gint ett_tcp_segment  = -1;
static gint ett_ctp_outer  = -1;
static gint ett_ctp_inner  = -1;

static int hf_tcp_segments = -1;

static int hf_tcp_segment = -1;
static int hf_tcp_segment_overlap = -1;
static int hf_tcp_segment_overlap_conflict = -1;
static int hf_tcp_segment_multiple_tails = -1;
static int hf_tcp_segment_too_long_fragment = -1;
static int hf_tcp_segment_error = -1;
static int hf_tcp_segment_count = -1;

static int hf_tcp_reassembled_in = -1;
static int hf_tcp_reassembled_length = -1;
static int hf_tcp_reassembled_data = -1;


static const fragment_items stltp_segment_items = {
	&ett_tcp_segment,
	&ett_tcp_segments,
	&hf_tcp_segments,
	&hf_tcp_segment,
	&hf_tcp_segment_overlap,
	&hf_tcp_segment_overlap_conflict,
	&hf_tcp_segment_multiple_tails,
	&hf_tcp_segment_too_long_fragment,
	&hf_tcp_segment_error,
	&hf_tcp_segment_count,
	&hf_tcp_reassembled_in,
	&hf_tcp_reassembled_length,
	&hf_tcp_reassembled_data,
	"Segments"
};

/* Code to actually dissect the packets */
/* ==================================== */
static int
dissect_atsc3_stltp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int                 len;

    /* Offset for subpacket dissection */
    guint offset = 0;

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *stltp_outer_tree;


    tvbuff_t *new_tvb;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATSC3 STLTP");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_atsc3_stltp, tvb, offset, -1, ENC_NA);

    proto_tree* stltp_tree = proto_item_add_subtree(ti, ett_main);

    stltp_outer_tree = proto_tree_add_subtree(stltp_tree, tvb, 0, 0, ett_ctp_outer,  NULL, "CTP Outer");

    proto_tree_add_item(stltp_outer_tree, hf_ctp_outer_fixed_header_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(stltp_outer_tree, hf_ctp_outer_fixed_header_padding, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(stltp_outer_tree, hf_ctp_outer_fixed_header_extension, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(stltp_outer_tree, hf_ctp_outer_fixed_header_csrc_count, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item_ret_uint(stltp_outer_tree, hf_ctp_outer_fixed_header_marker, tvb, offset, 1, ENC_BIG_ENDIAN, &ctp_outer_fixed_header_marker);
    proto_tree_add_item_ret_uint(stltp_outer_tree, hf_ctp_outer_fixed_header_payload_type, tvb, offset, 1, ENC_BIG_ENDIAN, &ctp_outer_fixed_header_payload_type);
    offset++;
    proto_tree_add_item_ret_uint(stltp_outer_tree, hf_ctp_outer_fixed_header_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN, &ctp_outer_fixed_header_sequence_number);
    offset += 2;

    if(ctp_outer_fixed_header_payload_type == ATSC3_STLTP_CTP_OUTER_PAYLOAD_TYPE_DSTP || ctp_outer_fixed_header_payload_type == ATSC3_STLTP_CTP_OUTER_PAYLOAD_TYPE_ALPTP) {
    	//timestamp_min()

        proto_tree_add_item(stltp_outer_tree, hf_ctp_outer_fixed_header_timestamp_min_seconds, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(stltp_outer_tree, hf_ctp_outer_fixed_header_timestamp_min_fraction, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;


    } else if(ctp_outer_fixed_header_payload_type == ATSC3_STLTP_CTP_OUTER_PAYLOAD_TYPE_STLTP) {
    	//timestamp()
        proto_tree_add_item(stltp_outer_tree, hf_ctp_outer_fixed_header_timestamp_seconds_pre, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(stltp_outer_tree, hf_ctp_outer_fixed_header_timestamp_a_milliseconds_seconds_pre, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    } else {
    	//reserved_32
        proto_tree_add_item(stltp_outer_tree, hf_ctp_outer_fixed_header_reserved_32b, tvb, offset, 4, ENC_BIG_ENDIAN);

    	offset += 4;
    }

    proto_tree_add_item(stltp_outer_tree, hf_ctp_outer_fixed_header_protocol_version, tvb, offset, 2, ENC_BIG_ENDIAN);

    if(ctp_outer_fixed_header_payload_type == ATSC3_STLTP_CTP_OUTER_PAYLOAD_TYPE_STLTP) {
        proto_tree_add_item(stltp_outer_tree, hf_ctp_outer_fixed_header_redundancy, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(stltp_outer_tree, hf_ctp_outer_fixed_header_number_of_channels, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(stltp_outer_tree, hf_ctp_outer_fixed_header_reserved_10, tvb, offset, 2, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(stltp_outer_tree, hf_ctp_outer_fixed_header_reserved_14, tvb, offset, 2, ENC_BIG_ENDIAN);
    }

    offset += 2;

    proto_tree_add_item_ret_uint(stltp_outer_tree, hf_ctp_outer_fixed_header_packet_offset, tvb, offset, 2, ENC_BIG_ENDIAN, &ctp_outer_fixed_header_packet_offset);
    offset += 2;

//    fragment_add_seq(table,
//    		tvb, offset, pinfo, id, data, frag_number, frag_data_len, more_frags, flags)

    fragment_head *fd_head = NULL;
//    pinfo->fd->visited = FALSE;


  //  tvbuff_t* tvb_subset = NULL;

//    if(ctp_outer_fixed_header_marker) {
//
//
//    } else {
//    	tvb_subset = tvb_new_subset_remaining(tvb, offset);
//    }
//
//    fd_head = fragment_add_seq_next(&stltp_ctp_outer_reassembly_table, tvb_subset, 0, pinfo, ctp_outer_fixed_header_payload_type, NULL, tvb_captured_length(tvb_subset), !ctp_outer_fixed_header_marker);



    //    fd_head = fragment_add_seq_next(&stltp_ctp_outer_reassembly_table,
//			tvb,
//			ctp_outer_fixed_header_sequence_number, &pinfo, ctp_outer_fixed_header_payload_type, NULL, ctp_outer_fixed_header_sequence_number, tvb_captured_length(tvb), !ctp_outer_fixed_header_marker, 0);

    //end of CTP outer

//    if(fd_head) {
//		proto_item *frag_tree_item;
//				show_fragment_tree(fd_head, &stltp_segment_items, stltp_outer_tree, pinfo, tvb, &frag_tree_item);
//    }

    if(ctp_outer_fixed_header_marker) {
    	col_append_fstr(pinfo->cinfo, COL_INFO, "CTP Outer: Seq: %5d, Marker, pos: %d", ctp_outer_fixed_header_sequence_number, ctp_outer_fixed_header_packet_offset);
    	tvbuff_t* tvb_last_subset = NULL;
    	tvb_last_subset = tvb_new_subset_length_caplen(tvb, offset, ctp_outer_fixed_header_packet_offset, ctp_outer_fixed_header_packet_offset);

    	//we can't put our 'current' split packet in the reassembly table, as it will be cross-linked when starting a new reassembly
    	fd_head = fragment_add_seq_next(&stltp_ctp_outer_reassembly_table, tvb_last_subset, 0, pinfo, ctp_outer_fixed_header_payload_type, NULL, tvb_captured_length(tvb_last_subset), FALSE);
    	//fd_head = fragment_add_multiple_ok(&stltp_ctp_outer_reassembly_table, tvb_last_subset, 0, pinfo, ctp_outer_fixed_header_payload_type, NULL, ctp_outer_fixed_header_sequence_number, tvb_captured_length(tvb_last_subset), FALSE);

    	fragment_head* reassy_head = fragment_end_seq_next(&stltp_ctp_outer_reassembly_table, pinfo, ctp_outer_fixed_header_payload_type, NULL);

    //	fragment_head* reassy_head = fragment_get_reassembled_id(&stltp_ctp_outer_reassembly_table, pinfo, ctp_outer_fixed_header_payload_type);
    	if(reassy_head) {
    		reassy_head->reassembled_in = pinfo->num;

        	proto_item *frag_tree_item;

        	gboolean update_col_info = TRUE;

           tvbuff_t* reassy_tvb = NULL;

           //todo - impl process_reassembeled_data but don't mark reassembeled pdu frame...
           //reassy_tvb = process_reassembled_data(tvb_last_subset, 0, pinfo, "Reassembled STLTP", reassy_head, &stltp_segment_items, &update_col_info, stltp_outer_tree);
           reassy_tvb = reassy_head->tvb_data;

           if(reassy_tvb) {
			   add_new_data_source(pinfo, reassy_tvb, "Reassy CTP Inner");
//jjustman-2022-09-13 - todo - combine reassy_tb with tvb_last_subset
			   col_append_fstr(pinfo->cinfo, COL_INFO, " Reassy TVB CTP Inner Len: %d ", tvb_captured_length(reassy_tvb));

		//	   show_fragment_tree(reassy_head, &stltp_segment_items, stltp_outer_tree, pinfo, tvb, &frag_tree_item);
			   //rtp header = 12 bytes
			   //ip_udp_rtp header = 40 bytes
			   //ip_udp header = 28 bytes
			   tvbuff_t* ip_udp_header_tvb = tvb_new_subset_length(reassy_tvb, 0, 28);

			   //cheat - this should be 28 :)
			   //hack - impl public ipv4 header parser subset...grrr

			//   guint reassy_offset = call_dissector_only(ip_handle, ip_udp_header_tvb, pinfo, tree, NULL);
			   	guint reassy_offset = 0;
			   	proto_tree* stltp_inner_tree = proto_tree_add_subtree(stltp_tree, reassy_tvb, 0, 0, ett_ctp_inner,  NULL, "CTP Inner");


			   	  //proto_tree_add_subtree(ti, tvb, 0, 0, , length, idx, tree_item, text)
//				   proto_tree* stltp_inner_tree = proto_item_add_subtree(ti, ett_main);
				   //proto_item_set_text(stltp_inner_tree, "CTP Inner");

				   proto_tree_add_item(stltp_inner_tree, hf_ip_version, reassy_tvb, reassy_offset, 1, ENC_BIG_ENDIAN);
				   proto_tree_add_item(stltp_inner_tree, hf_ip_hdr_len, reassy_tvb, reassy_offset, 1, ENC_BIG_ENDIAN);
				   proto_tree_add_item(stltp_inner_tree, hf_ip_src, reassy_tvb, reassy_offset + 12, 4, ENC_BIG_ENDIAN);
				   proto_tree_add_item(stltp_inner_tree, hf_ip_dst, reassy_tvb, reassy_offset + 16, 4, ENC_BIG_ENDIAN);
				   proto_tree_add_item(stltp_inner_tree, hf_ip_proto, reassy_tvb, reassy_offset + 9, 1, ENC_BIG_ENDIAN);

				   proto_tree_add_item(stltp_inner_tree, hf_ctp_inner_udp_source_port, reassy_tvb, reassy_offset + 20, 2, ENC_BIG_ENDIAN);
				   proto_tree_add_item(stltp_inner_tree, hf_ctp_inner_udp_dst_port, reassy_tvb, reassy_offset + 22, 2, ENC_BIG_ENDIAN);

			    //  item = proto_tree_add_ipv4(ip_tree, hf_ip_addr, tvb, offset + 12, 4, addr);

				   reassy_offset += 28;


//			   if(ip_try_dissect(TRUE, IP_VERSION_NUM_INET, reassy_tvb, pinfo, tree, iph)) {

				   //parse out our inner rtp header?

//inner
				   proto_tree_add_item(stltp_inner_tree, hf_ctp_outer_fixed_header_version, reassy_tvb, reassy_offset, 1, ENC_BIG_ENDIAN);
				   proto_tree_add_item(stltp_inner_tree, hf_ctp_outer_fixed_header_padding, reassy_tvb, reassy_offset, 1, ENC_BIG_ENDIAN);
				   proto_tree_add_item(stltp_inner_tree, hf_ctp_outer_fixed_header_extension, reassy_tvb, reassy_offset, 1, ENC_BIG_ENDIAN);
				   proto_tree_add_item(stltp_inner_tree, hf_ctp_inner_fixed_header_csrc_count, reassy_tvb, reassy_offset, 1, ENC_BIG_ENDIAN);
				   reassy_offset++;
				   proto_tree_add_item_ret_uint(stltp_inner_tree, hf_ctp_inner_fixed_header_marker, reassy_tvb, reassy_offset, 1, ENC_BIG_ENDIAN, &ctp_inner_fixed_header_marker);
				   proto_tree_add_item_ret_uint(stltp_inner_tree, hf_ctp_inner_fixed_header_payload_type, reassy_tvb, reassy_offset, 1, ENC_BIG_ENDIAN, &ctp_inner_fixed_header_payload_type);
				   reassy_offset++;
				   proto_tree_add_item_ret_uint(stltp_inner_tree, hf_ctp_outer_fixed_header_sequence_number, reassy_tvb, reassy_offset, 2, ENC_BIG_ENDIAN, &ctp_outer_fixed_header_sequence_number);
				   reassy_offset += 2;

				   col_append_fstr(pinfo->cinfo, COL_INFO, " Inner CTP: %s (0x%02x)", val_to_str(ctp_inner_fixed_header_payload_type, atsc3_stltp_ctp_inner_payload_type_mapping, "UNKNOWN"), ctp_inner_fixed_header_payload_type);

				   //timestamp()
				   proto_tree_add_item(stltp_inner_tree, hf_ctp_inner_fixed_header_timestamp_seconds_pre, reassy_tvb, reassy_offset, 4, ENC_BIG_ENDIAN);
				   proto_tree_add_item(stltp_inner_tree, hf_ctp_inner_fixed_header_timestamp_a_milliseconds_seconds_pre, reassy_tvb, reassy_offset, 4, ENC_BIG_ENDIAN);
				   reassy_offset += 4;


				   if(ctp_inner_fixed_header_payload_type == ATSC3_STLTP_CTP_INNER_PAYLOAD_TYPE_BASEBAND_PACKET && ctp_inner_fixed_header_marker) {
					   proto_tree_add_item_ret_uint(stltp_inner_tree, hf_ctp_inner_bbp_length, reassy_tvb, reassy_offset, 4, ENC_BIG_ENDIAN, &ctp_inner_bbp_length);

					   col_append_fstr(pinfo->cinfo, COL_INFO, " Len: %d", ctp_inner_bbp_length);
				   } else {

					   offset += 4; //skip these 4 bytes for SSRC
				   }

				   //parse thru inner payload types, and then parse thru any any additional RTP header frames...

				   //read thru reassy_tvb remaining to get any additional RTP headers for frames...

				// }

//			    proto_item* tree_item = proto_tree_get_parent(stltp_outer_tree);
//			    if(frag_tree_item && tree_item) {
//			        proto_tree_move_item(tree, tree_item, frag_tree_item);
//			    }
           }

           //jjustman-2022-09-13 - hack?
          	fragment_reset_defragmentation(reassy_head);
          	fragment_reset_defragmentation(fd_head);

        }


    	//start a new tvb from our ctp_outer_fixed_header_packet_offset
       	//doesnt work?
    	//fragment_delete(&stltp_ctp_outer_reassembly_table, pinfo, ctp_outer_fixed_header_payload_type, NULL);
   //     reassembly_table_destroy(&stltp_ctp_outer_reassembly_table);
   //     reassembly_table_init(&stltp_ctp_outer_reassembly_table, &addresses_reassembly_table_functions);



 //   	pinfo->fragmented = TRUE;
//    	pinfo->fd->visited = FALSE;

    	ctp_outer_fixed_header_packet_offset += 12;

    	tvbuff_t* tvb_inner_subset = tvb_new_subset_remaining(tvb, ctp_outer_fixed_header_packet_offset);

    	//parse this as IP/UDP/RTP header again..

    	//try and walk thru our reassembly
//    	fragment_add_seq(&stltp_ctp_outer_reassembly_table, tvb_inner_subset, 0, pinfo, ctp_outer_fixed_header_payload_type, NULL, 0, tvb_captured_length(tvb_inner_subset), TRUE, 0); //flags)
//    	fragment_add_seq(&stltp_ctp_outer_reassembly_table, tvb_inner_subset, 0, pinfo, ctp_outer_fixed_header_payload_type, NULL, tvb_captured_length(tvb_inner_subset), TRUE);
   // 	fd_head = fragment_add_multiple_ok(&stltp_ctp_outer_reassembly_table, tvb_inner_subset, 0, pinfo, ctp_outer_fixed_header_payload_type, NULL, ctp_outer_fixed_header_sequence_number, tvb_captured_length(tvb_inner_subset), TRUE);

    	//fd_head = fragment_add_multiple_ok(&stltp_ctp_outer_reassembly_table, tvb_inner_subset, 0, pinfo, ctp_outer_fixed_header_payload_type, NULL, tvb_captured_length(tvb_inner_subset), TRUE);

    	fd_head = fragment_add_seq_next(&stltp_ctp_outer_reassembly_table, tvb_inner_subset, 0, pinfo, ctp_outer_fixed_header_payload_type, NULL, tvb_captured_length(tvb_inner_subset), TRUE);

    	//        fd_head = fragment_add_seq_next(&stltp_ctp_outer_reassembly_table, tvb, 0, pinfo, ctp_outer_fixed_header_payload_type, NULL, tvb_captured_length(tvb), TRUE);


    //	fragment_add_check(table, tvb, offset, pinfo, id, data, frag_offset, frag_data_len, more_frags)
    //	fragment_add_seq_single_aging(&stltp_ctp_inner_reassembly_table, tvbuff_ctp_inner, ctp_outer_fixed_header_sequence_number,
    } else {

    	//ctp_outer_fixed_header_sequence_number
//    	fd_head = fragment_add_seq(&stltp_ctp_outer_reassembly_table, tvb, offset, pinfo, ctp_outer_fixed_header_payload_type, NULL, ctp_outer_fixed_header_sequence_number, tvb_captured_length(tvb), TRUE, 0);
        fd_head = fragment_add_seq_next(&stltp_ctp_outer_reassembly_table, tvb, offset, pinfo, ctp_outer_fixed_header_payload_type, NULL, tvb_captured_length_remaining(tvb, offset), TRUE);

    	//continuation
    	col_append_fstr(pinfo->cinfo, COL_INFO, "CTP Outer: Seq: %5d", ctp_outer_fixed_header_sequence_number);
    }

//
//    /* Add the Payload item */
//    if (tvb_reported_length(tvb) > offset){
//
//
//    	if(lls_table_id == 0x01 || lls_table_id==0x02 || lls_table_id == 0x03 || lls_table_id == 0x04) {
//    		//uncompress and display
//
//    		//col_append_fstr
//    		int gzip_len;
//    		tvbuff_t *next_tvb;
//
//    		gzip_len = tvb_captured_length_remaining(tvb, offset);
//            next_tvb = tvb_uncompress(tvb, offset, gzip_len);
//            if (next_tvb) {
//                add_new_data_source(pinfo, next_tvb, "compressed data");
//                proto_tree_add_item(lls_tree, hf_payload_str, next_tvb, 0, -1, ENC_STRING);
//
//                if(lls_table_id == 0x01) {
//					call_dissector_with_data(xml_handle, next_tvb, pinfo, lls_tree, NULL);
//
//					xml_dissector_frame = (xml_frame_t *)p_get_proto_data(pinfo->pool, pinfo, proto_xml, 0);
//					if(xml_dissector_frame == NULL) {
//						return tvb_captured_length(tvb);
//					} else {
//
//						if(has_added_lls_table_slt_version_conversations != lls_table_version) {
//							atsc_lls_slt_add_conversations_from_xml_dissector(xml_dissector_frame);
//						}
//						has_added_lls_table_slt_version_conversations = lls_table_version;
//					}
//                } else {
//                	call_dissector(xml_handle, next_tvb, pinfo, lls_tree);
//                }
//
//
//            } else {
//                expert_add_info(pinfo, ti, &ei_payload_decompress_failed);
//
//            }
//            offset += gzip_len;
//    	} else {
//            proto_tree_add_item(lls_tree, hf_payload, tvb, offset, -1, ENC_NA);
//        }
//    }

    return tvb_reported_length(tvb);
}


static void atsc3_stltp_init(void)
{
    reassembly_table_init(&stltp_ctp_outer_reassembly_table, &addresses_reassembly_table_functions);
    reassembly_table_init(&stltp_ctp_inner_reassembly_table, &addresses_reassembly_table_functions);

}

static void atsc3_stltp_cleanup(void)
{
    reassembly_table_destroy(&stltp_ctp_inner_reassembly_table);
    reassembly_table_destroy(&stltp_ctp_outer_reassembly_table);
}



void proto_register_atsc3_stltp(void)
{

    /* Setup ALC header fields */
    static hf_register_info hf_ptr[] = {

        { &hf_ctp_outer_fixed_header_version, 		 	{ "RTP Version", 		"stltp.ctp_outer.header.version", 			FT_UINT8,  BASE_DEC, NULL, 0xC0, NULL, HFILL }},
        { &hf_ctp_outer_fixed_header_padding, 			{ "padding_1", 			"stltp.ctp_outer.header.padding_1", 		FT_UINT8,  BASE_DEC, NULL, 0x20, NULL, HFILL }},
        { &hf_ctp_outer_fixed_header_extension, 		{ "Extension", 			"stltp.ctp_outer.header.version", 			FT_UINT8,  BASE_DEC, NULL, 0x10, NULL, HFILL }},
        { &hf_ctp_outer_fixed_header_csrc_count,  		{ "CSRC Count", 		"stltp.ctp_outer.header.csrc_count", 		FT_UINT8,  BASE_DEC, NULL, 0x0F, NULL, HFILL }},
        { &hf_ctp_outer_fixed_header_marker, 			{ "Marker", 			"stltp.ctp_outer.header.marker", 			FT_UINT8,  BASE_DEC, NULL, 0x80, NULL, HFILL }},
        { &hf_ctp_outer_fixed_header_payload_type, 		{ "Payload Type", 		"stltp.ctp_outer.header.payload_type", 		FT_UINT8,  BASE_DEC, atsc3_stltp_ctp_outer_payload_type_mapping, 0x7F, NULL, HFILL }},

        { &hf_ctp_outer_fixed_header_sequence_number,	{ "Sequence Number",	"stltp.ctp_outer.header.sequence_number", 	FT_UINT16, BASE_DEC, NULL, 0x0000, NULL, HFILL }},


        { &hf_ctp_outer_fixed_header_timestamp_min_seconds,	{ "Timestamp min seconds",	"stltp.ctp_outer.header.timestamp_min.seconds", 	FT_UINT16, BASE_DEC, NULL, 0x0000, NULL, HFILL }},
        { &hf_ctp_outer_fixed_header_timestamp_min_fraction,{ "Timestamp min fraction",	"stltp.ctp_outer.header.timestamp_min.fraction", 	FT_UINT16, BASE_DEC, NULL, 0x0000, NULL, HFILL }},


//timestamp() {
		//22 msb
        { &hf_ctp_outer_fixed_header_timestamp_seconds_pre,					{ "Seconds",			"stltp.ctp_outer.header.timestamp.seconds_pre", 		FT_UINT32, BASE_DEC, NULL, 0xFFFFFC00, NULL, HFILL }},
		//remaining 10 lsb
		{ &hf_ctp_outer_fixed_header_timestamp_a_milliseconds_seconds_pre,	{ "a milliseconds pre",	"stltp.ctp_outer.header.timestamp.a_milliseconds_pre", 	FT_UINT32, BASE_DEC, NULL, 0x000003FF, NULL, HFILL }},
//}
    		//reserved
		{ &hf_ctp_outer_fixed_header_reserved_32b,							{ "Reserved 32b",		"stltp.ctp_outer.header.reserved_32b", 					FT_UINT32, BASE_DEC, NULL, 0x00000000, NULL, HFILL }},

		//
        { &hf_ctp_outer_fixed_header_protocol_version, 		{ "Protocol Version", 		"stltp.ctp_outer.header.protocol_version", 		FT_UINT16,  BASE_DEC, NULL, 0xC000, NULL, HFILL }},

		//if pt==STLTP
		{ &hf_ctp_outer_fixed_header_redundancy, 			{ "Redundancy", 			"stltp.ctp_outer.header.redundancy", 			FT_UINT16,  BASE_DEC, NULL, 0x3000, NULL, HFILL }},
		{ &hf_ctp_outer_fixed_header_number_of_channels, 	{ "Number of channels", 	"stltp.ctp_outer.header.number_of_channels", 	FT_UINT16,  BASE_DEC, NULL, 0x0C00, NULL, HFILL }},
		{ &hf_ctp_outer_fixed_header_reserved_10, 			{ "reserved_10", 			"stltp.ctp_outer.header.reserved_10", 			FT_UINT16,  BASE_DEC, NULL, 0x03FF, NULL, HFILL }},

		//else
		{ &hf_ctp_outer_fixed_header_reserved_14, 			{ "reserved_14", 			"stltp.ctp_outer.header.reserved_14", 			FT_UINT16,  BASE_DEC, NULL, 0x3FFF, NULL, HFILL }},

		{ &hf_ctp_outer_fixed_header_packet_offset, 		{ "Packet Offset", 			"stltp.ctp_outer.header.packet_offset", 		FT_UINT16,  BASE_DEC, NULL, 0x0000, NULL, HFILL }},



        { &hf_ctp_inner_fixed_header_csrc_count,  		{ "CSRC Count", 		"stltp.ctp.inner.header.csrc_count", 		FT_UINT8,  BASE_DEC, NULL, 0x0F, NULL, HFILL }},
        { &hf_ctp_inner_fixed_header_marker, 			{ "Marker", 			"stltp.ctp.inner.header.marker", 			FT_UINT8,  BASE_DEC, NULL, 0x80, NULL, HFILL }},

		//atsc3_stltp_ctp_inner_payload_type_mapping
        { &hf_ctp_inner_fixed_header_payload_type, 		{ "Payload Type", 		"stltp.ctp.inner.header.payload_type", 		FT_UINT8,  BASE_DEC, atsc3_stltp_ctp_inner_payload_type_mapping, 0x7F, NULL, HFILL }},


//timestamp() {
		//22 msb
		{ &hf_ctp_inner_fixed_header_timestamp_seconds_pre,					{ "Seconds",			"stltp.ctp.inner.header.timestamp.seconds_pre", 		FT_UINT32, BASE_DEC, NULL, 0xFFFFFC00, NULL, HFILL }},
		//remaining 10 lsb
		{ &hf_ctp_inner_fixed_header_timestamp_a_milliseconds_seconds_pre,	{ "a milliseconds pre",	"stltp.ctp.inner.header.timestamp.a_milliseconds_pre", 	FT_UINT32, BASE_DEC, NULL, 0x000003FF, NULL, HFILL }},
//}

		{ &hf_ctp_inner_bbp_length,		{ "BBP Length", 			"stltp.ctp_outer.header.bbp_length", 		FT_UINT32,  BASE_DEC, NULL, 0x0000, NULL, HFILL }},



		//ipv4

				{ &hf_ip_version,
						{ "Version", "ctp.inner.ip.version", FT_UINT8, BASE_DEC,
								NULL, 0xF0, NULL, HFILL }},

				{ &hf_ip_hdr_len,
						{ "Header Length", "ctp.inner.ip.hdr_len", FT_UINT8, BASE_DEC,
								NULL, 0x0, NULL, HFILL }},

				{ &hf_ip_dst,
						{ "Destination", "ctp.inner.ip.dst", FT_IPv4, BASE_NONE,
								NULL, 0x0, NULL, HFILL }},


				{ &hf_ip_src,
						{ "Source", "ctp.inner.ip.src", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},

				 { &hf_ip_proto,
					  { "Protocol", "ctp.inner.ip.proto", FT_UINT8, BASE_DEC,
						NULL, 0x0, NULL, HFILL }},

				{ &hf_ip_len,
						{ "Total Length", "ctp.inner.ip.len", FT_UINT16, BASE_DEC,
								NULL, 0x0, NULL, HFILL }},


				{&hf_ctp_inner_udp_source_port, { "Source Port", "ctp.inner.udp.srcport", FT_UINT16, BASE_PT_UDP, NULL, 0x0, NULL, HFILL }						},
				{&hf_ctp_inner_udp_dst_port,  { "Dest Port", "ctp.inner.udp.dstport", FT_UINT16, BASE_PT_UDP, NULL, 0x0, NULL, HFILL }						},

		//for reassembly debugging

		   { &hf_tcp_segment,
		        { "TCP Segment", "tcp.segment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		            NULL, HFILL }},

		        { &hf_tcp_segments,
		        { "Reassembled TCP Segments", "tcp.segments", FT_NONE, BASE_NONE, NULL, 0x0,
		            "TCP Segments", HFILL }},

		        { &hf_tcp_reassembled_in,
		        { "Reassembled PDU in frame", "tcp.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		            "The PDU that doesn't end in this segment is reassembled in this frame", HFILL }},

		        { &hf_tcp_reassembled_length,
		        { "Reassembled TCP length", "tcp.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
		            "The total length of the reassembled payload", HFILL }},

		        { &hf_tcp_reassembled_data,
		        { "Reassembled TCP Data", "tcp.reassembled.data", FT_BYTES, BASE_NONE, NULL, 0x0,
		            "The reassembled payload", HFILL }},

					   { &hf_tcp_segment_overlap,
					        { "Segment overlap",    "tcp.segment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
					            "Segment overlaps with other segments", HFILL }},

					        { &hf_tcp_segment_overlap_conflict,
					        { "Conflicting data in segment overlap",    "tcp.segment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
					            "Overlapping segments contained conflicting data", HFILL }},

					        { &hf_tcp_segment_multiple_tails,
					        { "Multiple tail segments found",   "tcp.segment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
					            "Several tails were found when reassembling the pdu", HFILL }},

					        { &hf_tcp_segment_too_long_fragment,
					        { "Segment too long",   "tcp.segment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
					            "Segment contained data past end of the pdu", HFILL }},

					        { &hf_tcp_segment_error,
					        { "Reassembling error", "tcp.segment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
					            "Reassembling error due to illegal segments", HFILL }},

					        { &hf_tcp_segment_count,
					        { "Segment count", "tcp.segment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
					            NULL, HFILL }},

					        { &hf_tcp_segment,
					        { "TCP Segment", "tcp.segment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
					            NULL, HFILL }},

					        { &hf_tcp_segments,
					        { "Reassembled TCP Segments", "tcp.segments", FT_NONE, BASE_NONE, NULL, 0x0,
					            "TCP Segments", HFILL }},

					        { &hf_tcp_reassembled_in,
					        { "Reassembled PDU in frame", "tcp.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
					            "The PDU that doesn't end in this segment is reassembled in this frame", HFILL }},

					        { &hf_tcp_reassembled_length,
					        { "Reassembled TCP length", "tcp.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
					            "The total length of the reassembled payload", HFILL }},

					        { &hf_tcp_reassembled_data,
					        { "Reassembled TCP Data", "tcp.reassembled.data", FT_BYTES, BASE_NONE, NULL, 0x0,
					            "The reassembled payload", HFILL }},


    };

    /* Setup protocol subtree array */
    static gint *ett_ptr[] = {
        &ett_main,
	    &ett_tcp_segments,
        &ett_tcp_segment,
		&ett_ctp_outer,
		&ett_ctp_inner,

    };


    module_t *module;
    expert_module_t* expert_rmt_alc;

    register_init_routine(&atsc3_stltp_init);
    register_cleanup_routine(&atsc3_stltp_cleanup);

    /* Register the protocol name and description */
    proto_atsc3_stltp = proto_register_protocol("ATSC 3.0 STLTP", "atsc3-stltp", "atsc3-stltp");
    register_dissector("atsc3-stltp", dissect_atsc3_stltp, proto_atsc3_stltp);

    /* Register the header fields and subtrees used */
    proto_register_field_array(proto_atsc3_stltp, hf_ptr, array_length(hf_ptr));
    proto_register_subtree_array(ett_ptr, array_length(ett_ptr));

    static ei_register_info ei[] = {
        { &ei_payload_decompress_failed, { "lls.decompress_failed", PI_PROTOCOL, PI_WARN, "Unable to decompress LLS payload", EXPFILL }},
    };

    expert_rmt_alc = expert_register_protocol(proto_atsc3_stltp);
    expert_register_field_array(expert_rmt_alc, ei, array_length(ei));

    /* Register preferences */
    module = prefs_register_protocol(proto_atsc3_stltp, NULL);

//    prefs_register_obsolete_preference(module, "default.udp_port.enabled");
//
//    prefs_register_bool_preference(module,
//                                   "lct.codepoint_as_fec_id",
//                                   "LCT Codepoint as FEC Encoding ID",
//                                   "Whether the LCT header Codepoint field should be considered the FEC Encoding ID of carried object",
//                                   &g_codepoint_as_fec_encoding);
//
//    prefs_register_enum_preference(module,
//                                   "lct.ext.192",
//                                   "LCT header extension 192",
//                                   "How to decode LCT header extension 192",
//                                   &g_ext_192,
//                                   enum_lct_ext_192,
//                                   FALSE);
//
//    prefs_register_enum_preference(module,
//                                   "lct.ext.193",
//                                   "LCT header extension 193",
//                                   "How to decode LCT header extension 193",
//                                   &g_ext_193,
//                                   enum_lct_ext_193,
//                                   FALSE);
}

void proto_reg_handoff_atsc3_stltp(void)
{
    dissector_handle_t handle;

    handle = create_dissector_handle(dissect_atsc3_stltp, proto_atsc3_stltp);

    dissector_add_uint("udp.port", ATSC3_LLS_UDP_PORT, handle);

    ip_handle = find_dissector("ip");


//
//    //    dissector_add_for_decode_as_with_preference("udp.port", handle);
//    xml_handle = find_dissector_add_dependency("xml", proto_atsc3_lls);
//
//    atsc3_route_dissector_handle = find_dissector_add_dependency("atsc3-route", proto_atsc3_lls);
//    atsc3_mmtp_dissector_handle = find_dissector_add_dependency("atsc3-mmtp", proto_atsc3_lls);
//

//	rmt_lct_handle = find_dissector_add_dependency("atsc3-lct", proto_atsc3_route);
//    rmt_fec_handle = find_dissector_add_dependency("atsc3-fec", proto_atsc3_route);
}

/*
 * Editor modelines - https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
