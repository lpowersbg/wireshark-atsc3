/* packet-atsc3-route.c
 * ATSC 3.0
 * ROUTE Protocol Instantiation dissector
 * Copyright 2022, Jason Justman <jjustman@ngbp.org>
 *
 * Based off of A/331:2022-03
 *
 * References:
 *
 * Asynchronous Layered Coding (ALC):
 * ----------------------------------
 *
 * A massively scalable reliable content delivery protocol.
 * Asynchronous Layered Coding combines the Layered Coding Transport
 * (LCT) building block, a multiple rate congestion control building
 * block and the Forward Error Correction (FEC) building block to
 * provide congestion controlled reliable asynchronous delivery of
 * content to an unlimited number of concurrent receivers from a single
 * sender.
 *
 * References:
 *     RFC 3450, Asynchronous Layered Coding protocol instantiation
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

#include "packet-atsc3-common.h"

/* Initialize the protocol and registered fields */
/* ============================================= */

void proto_register_atsc3_route(void);
void proto_reg_handoff_atsc3_route(void);

int proto_atsc3_route = -1;

static int hf_version = -1;
static int hf_start_offset = -1;
static int hf_payload = -1;
static int hf_payload_str = -1;


static int ett_main = -1;
static int ett_sls = -1;

static expert_field ei_version1_only = EI_INIT;

static dissector_handle_t xml_handle;
static dissector_handle_t rmt_lct_handle;
static dissector_handle_t rmt_fec_handle;

static gboolean g_codepoint_as_fec_encoding = FALSE;
static gint     g_ext_192                   = LCT_PREFS_EXT_192_FLUTE;
static gint     g_ext_193                   = LCT_PREFS_EXT_193_FLUTE;

static reassembly_table route_sls_reassembly_table = { 0 };

static gint hf_mp_fragments = -1;
static gint hf_mp_fragment = -1;
static gint hf_mp_fragment_overlap = -1;
static gint hf_mp_fragment_overlap_conflicts = -1;
static gint hf_mp_fragment_multiple_tails = -1;
static gint hf_mp_fragment_too_long_fragment = -1;
static gint hf_mp_fragment_error = -1;
static gint hf_mp_fragment_count = -1;
static gint hf_mp_reassembled_in = -1;
static gint hf_mp_reassembled_length = -1;

static int ett_mp = -1;
static int ett_mp_flags = -1;
static gint ett_mp_fragment = -1;
static gint ett_mp_fragments = -1;

static const fragment_items mp_frag_items = {
    /* Fragment subtrees */
    &ett_mp_fragment,
    &ett_mp_fragments,
    /* Fragment fields */
    &hf_mp_fragments,
    &hf_mp_fragment,
    &hf_mp_fragment_overlap,
    &hf_mp_fragment_overlap_conflicts,
    &hf_mp_fragment_multiple_tails,
    &hf_mp_fragment_too_long_fragment,
    &hf_mp_fragment_error,
    &hf_mp_fragment_count,
    /* Reassembled in field */
    &hf_mp_reassembled_in,
    /* Reassembled length field */
    &hf_mp_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "Message fragments"
};


static void atsc3_route_init(void)
{
	//addresses_reassembly_table_functions
	//addresses_ports_reassembly_table_functions
    reassembly_table_init(&route_sls_reassembly_table, &addresses_ports_reassembly_table_functions);

}

static void atsc3_route_cleanup(void)
{
    reassembly_table_destroy(&route_sls_reassembly_table);
}


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


/* Code to actually dissect the packets */
/* ==================================== */
static int
dissect_atsc3_route(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8              version;
    lct_data_exchange_t lct;
    fec_data_exchange_t fec;
    int                 len;

    guint32				lct_recovery_start_offset = 0;

    /* Offset for subpacket dissection */
    guint offset = 0;

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *route_tree;

    tvbuff_t *new_tvb;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATSC3 ROUTE");
    col_clear(pinfo->cinfo, COL_INFO);

    /* ALC header dissection */
    /* --------------------- */

    version = hi_nibble(tvb_get_guint8(tvb, offset));

    /* Create subtree for the ALC protocol */
    ti = proto_tree_add_item(tree, proto_atsc3_route, tvb, offset, -1, ENC_NA);
    route_tree = proto_item_add_subtree(ti, ett_main);

    /* Fill the ALC subtree */
    ti = proto_tree_add_uint(route_tree, hf_version, tvb, offset, 1, version);

    /* This dissector supports only ALCv1 packets.
     * If version > 1 print only version field and quit.
     */
    if (version != 1) {
        expert_add_info(pinfo, ti, &ei_version1_only);

        /* Complete entry in Info column on summary display */
        col_add_fstr(pinfo->cinfo, COL_INFO, "Version: %u (not supported)", version);
        return 0;
    }

    /* LCT header dissection */
    /* --------------------- */
    new_tvb = tvb_new_subset_remaining(tvb,offset);

    lct.ext_192 = g_ext_192;
    lct.ext_193 = g_ext_193;
    lct.codepoint = 0;
    lct.is_flute = FALSE;
    len = call_dissector_with_data(rmt_lct_handle, new_tvb, pinfo, route_tree, &lct);
    if (len < 0)
        return offset;

    offset += len;

    /* FEC header dissection */
    /* --------------------- */

    /* Only if LCT dissector has determined FEC Encoding ID */
    /* FEC dissector needs to be called with encoding_id filled */
    if (g_codepoint_as_fec_encoding && tvb_reported_length(tvb) > offset)
    {
        fec.encoding_id = lct.codepoint;

        new_tvb = tvb_new_subset_remaining(tvb,offset);
        len = call_dissector_with_data(rmt_fec_handle, new_tvb, pinfo, route_tree, &fec);
        if (len < 0)
            return offset;

        offset += len;
    } else if(tvb_reported_length(tvb) > offset) {
    	//use FEC Payload ID as start offset or sbn/esi
    	//if(lct.codepoint == 128) {
    	proto_tree_add_item(route_tree, hf_start_offset, tvb, offset,   4, ENC_BIG_ENDIAN);

    	lct_recovery_start_offset = tvb_get_ntohl(tvb, offset);
    	col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "Start Offset: %u", lct_recovery_start_offset);

    	offset += 4;
    }

    /* Add the Payload item */
    if (tvb_reported_length(tvb) > offset){
    	//we have an ext_fdt header (192)
        if(lct.is_flute){
            new_tvb = tvb_new_subset_remaining(tvb,offset);
            call_dissector(xml_handle, new_tvb, pinfo, route_tree);
        } else {

        	if(lct.tsi == 0) {

        		//pinfo->fd->visited = FALSE; //jjustman-2022-10-21 - HACK!
            	tvbuff_t* tvb_sls_inner_subset = tvb_new_subset_remaining(tvb, offset);
            	guint remaining_payload_length = tvb_reported_length(tvb_sls_inner_subset);

                fragment_head *fd_head = NULL;

        		if(lct.close_object_flag || ((lct.has_ext_tol_24 || lct.has_ext_tol_48) && (lct_recovery_start_offset + remaining_payload_length) >= lct.tol)) {
        			//build our re-assembly here
        			//hack-ish
//        			fragment_head* reassy_head = fragment_add(&route_sls_reassembly_table, tvb_sls_inner_subset, 0, pinfo, lct.toi +lct.tsi, NULL, lct_recovery_start_offset, tvb_captured_length(tvb_sls_inner_subset), FALSE)

        			//fragment_add_multiple_ok
        			//atsc3-lct.tsi==0
        			//jjustman-2022-12-19 - 23.49 fragment_add_multiple_ok

        			//fragment_add_check
        			//fragment_head* reassy_head = fragment_add_multiple_ok(&route_sls_reassembly_table, tvb, offset, pinfo, lct.tsi, NULL, lct_recovery_start_offset, tvb_captured_length_remaining(tvb, offset), FALSE);

        			//fragment_head* reassy_head = fragment_add(&route_sls_reassembly_table, tvb, offset, pinfo, lct.toi, NULL, lct_recovery_start_offset, tvb_captured_length_remaining(tvb, offset), FALSE);
        	    	fd_head = fragment_add_seq_next(&route_sls_reassembly_table, tvb, offset, pinfo, lct.toi, NULL, tvb_captured_length_remaining(tvb, offset), FALSE);

        	    	fragment_head* reassy_head = fragment_end_seq_next(&route_sls_reassembly_table, pinfo, lct.toi, NULL);

					//fragment_add_seq(table, tvb, offset, pinfo, id, data, frag_number, frag_data_len, more_frags, flags)
        			//fragment_head* reassy_head = fragment_end_seq_next(&route_sls_reassembly_table, pinfo, lct.toi, NULL);
        	    	if(reassy_head) {
						reassy_head->reassembled_in = pinfo->num;

						proto_item *frag_tree_item;

						gboolean update_col_info = TRUE;

						tvbuff_t* reassy_tvb = NULL;

						//todo - impl process_reassembeled_data but don't mark reassembeled pdu frame...
						//0143 - reassy_tvb = process_reassembled_data(tvb_sls_inner_subset, 0, pinfo, "Reassembled SLS", reassy_head, &mp_frag_items, NULL, route_tree);

						//			process_reassembled_data(tvb, offset, pinfo, name, fd_head, fit, update_col_infop, tree)
						//reassy_tvb = tvb_clone(reassy_head->tvb_data);

						reassy_tvb = reassy_head->tvb_data;

						if(reassy_tvb) {
							//tvbuff_t* reassy_tvb2 = tvb_clone(reassy_tvb);

							//reassy_tvb = tvb_clone(reassy_tvb);

							g_debug("adding SLS reassy: reassy_tvb len: %d", tvb_captured_length(reassy_tvb));

							add_new_data_source(pinfo, reassy_tvb, "Reassy SLS");
        	    	   	   //jjustman-2022-09-13 - todo - combine reassy_tb with tvb_last_subset
							col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "Reassy SLS Len: %d ", tvb_captured_length(reassy_tvb));


//        	   			   	proto_tree* route_sls_inner_tree = proto_tree_add_subtree(route_tree, reassy_tvb, 0, -1, ett_sls,  NULL, "Reassy SLS");
//
//        	           		proto_tree_add_item(route_sls_inner_tree, hf_payload, reassy_tvb, 0, tvb_captured_length(reassy_tvb), ENC_NA);
			        		proto_tree_add_item(route_tree, hf_payload, tvb, offset, -1, ENC_NA);

//        	        		proto_tree_add_item(route_tree, hf_payload, reassy_tvb2, 0, -1, ENC_NA);

						}

						fragment_reset_defragmentation(reassy_head);

        	    	}

        	    	if(fd_head) {
			          	//fragment_reset_defragmentation(fd_head);

        	    	}
					fragment_delete(&route_sls_reassembly_table, pinfo, lct.toi, NULL);

        		} else {

            		//append to re-assembly buffer
           	    	//fd_head = fragment_add(&route_sls_reassembly_table, tvb_sls_inner_subset, 0, pinfo, lct.toi + lct.tsi, NULL, lct_recovery_start_offset, tvb_captured_length(tvb_sls_inner_subset), TRUE);

        			//jjustman-2022-12-19 - 23.49 fragment_add_multiple_ok

            		//fragment_head* reassy_head = fragment_add_multiple_ok(&route_sls_reassembly_table, tvb, offset, pinfo, lct.tsi, NULL, lct_recovery_start_offset, tvb_captured_length_remaining(tvb, offset), TRUE);
//fragment_add_check
            		//fragment_head* reassy_head = fragment_add(&route_sls_reassembly_table, tvb, offset, pinfo, lct.toi, NULL, lct_recovery_start_offset, tvb_captured_length_remaining(tvb, offset), TRUE);
                    fragment_head* reassy_head = fragment_add_seq_next(&route_sls_reassembly_table, tvb, offset, pinfo, lct.toi, NULL, tvb_captured_length_remaining(tvb, offset), TRUE);
            		proto_tree_add_item(route_tree, hf_payload, tvb, offset, -1, ENC_NA);


           	    	g_info("pending route sls tsi:0, reassy_head is: %p", reassy_head);
        		}

        	} else {
        		proto_tree_add_item(route_tree, hf_payload, tvb, offset, -1, ENC_NA);
        	}
        }
    }

    return tvb_reported_length(tvb);
}

void proto_register_atsc3_route(void)
{
    /* Setup ALC header fields */
    static hf_register_info hf_ptr[] = {

        { &hf_version,
          { "Version", "alc.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_start_offset,
		  { "Start Offset", "atsc3-route.start_offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_payload,
          { "Payload", "alc.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_payload_str,
          { "Payload", "alc.payload", FT_STRING, STR_ASCII, NULL, 0x0, NULL, HFILL }},


//		  { &hf_mp_frag,
//		              { "Fragment", "mp.frag", FT_UINT8, BASE_HEX,
//		                  NULL, MP_FRAG_MASK, NULL, HFILL }},
//		          { &hf_mp_frag_short,
//		              { "Fragment", "mp.frag", FT_UINT8, BASE_HEX,
//		                  NULL, MP_FRAG_MASK_SHORT, NULL, HFILL }},
//		          { &hf_mp_frag_first,
//		              { "First fragment", "mp.first", FT_BOOLEAN, 8,
//		                  TFS(&tfs_yes_no), MP_FRAG_FIRST, NULL, HFILL }},
//		          { &hf_mp_frag_last,
//		              { "Last fragment", "mp.last", FT_BOOLEAN, 8,
//		                  TFS(&tfs_yes_no), MP_FRAG_LAST, NULL, HFILL }},
//		          { &hf_mp_sequence_num,
//		              { "Sequence number", "mp.seq", FT_UINT24, BASE_DEC,
//		                  NULL, 0x0, NULL, HFILL }},
//		          { &hf_mp_sequence_num_cls,
//		              { "Class", "mp.sequence_num_cls", FT_UINT8, BASE_DEC,
//		                  NULL, MP_FRAG_CLS, NULL, HFILL }},
//		          { &hf_mp_sequence_num_reserved,
//		              { "Reserved", "mp.sequence_num_reserved", FT_BOOLEAN, 8,
//		                  NULL, MP_FRAG_RESERVED, NULL, HFILL }},
//		          { &hf_mp_short_sequence_num,
//		              { "Short Sequence number", "mp.sseq", FT_UINT16, BASE_DEC,
//		                  NULL, 0x0FFF, NULL, HFILL }},
//		          { &hf_mp_short_sequence_num_cls,
//		              { "Class", "mp.short_sequence_num_cls", FT_UINT8, BASE_DEC,
//		                  NULL, MP_FRAG_CLS_SHORT, NULL, HFILL }},
//		          { &hf_mp_payload,
//		              {"Payload", "mp.payload", FT_BYTES, BASE_NONE,
//		                  NULL, 0x00, NULL, HFILL }},
		          { &hf_mp_fragments,
		              {"Message fragments", "mp.fragments", FT_NONE, BASE_NONE,
		                  NULL, 0x00, NULL, HFILL }},
		          { &hf_mp_fragment,
		            {"Message fragment", "mp.fragment", FT_FRAMENUM, BASE_NONE,
		                  NULL, 0x00, NULL, HFILL }},
		          { &hf_mp_fragment_overlap,
		            {"Message fragment overlap", "mp.fragment.overlap",
		                  FT_BOOLEAN, BASE_NONE,
		                  NULL, 0x00, NULL, HFILL }},
		          { &hf_mp_fragment_overlap_conflicts,
		            {"Message fragment overlapping with conflicting data", "mp.fragment.overlap.conflicts",
		                  FT_BOOLEAN, BASE_NONE,
		                  NULL, 0x00, NULL, HFILL }},
		          { &hf_mp_fragment_multiple_tails,
		            {"Message has multiple tail fragments", "mp.fragment.multiple_tails",
		                  FT_BOOLEAN, BASE_NONE,
		                  NULL, 0x00, NULL, HFILL }},
		          { &hf_mp_fragment_too_long_fragment,
		            {"Message fragment too long", "mp.fragment.too_long_fragment",
		                  FT_BOOLEAN, BASE_NONE,
		                  NULL, 0x00, NULL, HFILL }},
		          { &hf_mp_fragment_error,
		            {"Message defragmentation error", "mp.fragment.error",
		                  FT_FRAMENUM, BASE_NONE,
		                  NULL, 0x00, NULL, HFILL }},
		          { &hf_mp_fragment_count,
		            {"Message fragment count", "mp.fragment.count", FT_UINT32, BASE_DEC,
		                  NULL, 0x00, NULL, HFILL }},
		          { &hf_mp_reassembled_in,
		            {"Reassembled in", "mp.reassembled.in", FT_FRAMENUM, BASE_NONE,
		                  NULL, 0x00, NULL, HFILL }},
		          { &hf_mp_reassembled_length,
		            {"Reassembled length", "mp.reassembled.length", FT_UINT32, BASE_DEC,
		                  NULL, 0x00, NULL, HFILL }}
    };

    /* Setup protocol subtree array */
    static gint *ett_ptr[] = {
        &ett_main,
		&ett_sls,
        &ett_mp,
        &ett_mp_flags,
        &ett_mp_fragment,
        &ett_mp_fragments
    };

    static ei_register_info ei[] = {
        { &ei_version1_only, { "alc.version1_only", PI_PROTOCOL, PI_WARN, "Sorry, this dissector supports ALC version 1 only", EXPFILL }},
    };

    module_t *module;
    expert_module_t* expert_rmt_alc;

    register_init_routine(&atsc3_route_init);
    register_cleanup_routine(&atsc3_route_cleanup);


    /* Register the protocol name and description */
    proto_atsc3_route = proto_register_protocol("ATSC 3.0 ROUTE", "atsc3-route", "atsc3-route");
    register_dissector("atsc3-route", dissect_atsc3_route, proto_atsc3_route);

    /* Register the header fields and subtrees used */
    proto_register_field_array(proto_atsc3_route, hf_ptr, array_length(hf_ptr));
    proto_register_subtree_array(ett_ptr, array_length(ett_ptr));
    expert_rmt_alc = expert_register_protocol(proto_atsc3_route);
    expert_register_field_array(expert_rmt_alc, ei, array_length(ei));

    /* Register preferences */
    module = prefs_register_protocol(proto_atsc3_route, NULL);

    prefs_register_obsolete_preference(module, "default.udp_port.enabled");

    prefs_register_bool_preference(module,
                                   "lct.codepoint_as_fec_id",
                                   "LCT Codepoint as FEC Encoding ID",
                                   "Whether the LCT header Codepoint field should be considered the FEC Encoding ID of carried object",
                                   &g_codepoint_as_fec_encoding);

    prefs_register_enum_preference(module,
                                   "lct.ext.192",
                                   "LCT header extension 192",
                                   "How to decode LCT header extension 192",
                                   &g_ext_192,
                                   enum_lct_ext_192,
                                   FALSE);

    prefs_register_enum_preference(module,
                                   "lct.ext.193",
                                   "LCT header extension 193",
                                   "How to decode LCT header extension 193",
                                   &g_ext_193,
                                   enum_lct_ext_193,
                                   FALSE);
}

void proto_reg_handoff_atsc3_route(void)
{
    dissector_handle_t handle;

    handle = create_dissector_handle(dissect_atsc3_route, proto_atsc3_route);
    dissector_add_for_decode_as_with_preference("udp.port", handle);
    xml_handle = find_dissector_add_dependency("xml", proto_atsc3_route);
	rmt_lct_handle = find_dissector_add_dependency("atsc3-lct", proto_atsc3_route);
    rmt_fec_handle = find_dissector_add_dependency("atsc3-fec", proto_atsc3_route);
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
