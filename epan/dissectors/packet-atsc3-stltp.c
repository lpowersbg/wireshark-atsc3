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

/* Initialize the protocol and registered fields */
/* ============================================= */

void proto_register_atsc3_lls(void);
void proto_reg_handoff_atsc3_lls(void);

static int proto_atsc3_stltp = -1;

static int hf_lls_table_id = -1;
static int hf_lls_group_id = -1;
static int hf_lls_group_count_minus1 = -1;
static int hf_lls_table_version = -1;


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
    stltp_outer_tree = proto_item_add_subtree(ti, ett_main);

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
    	//timestamp
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

    //end of CTP outer

    if(ctp_outer_fixed_header_marker) {
    	ctp_outer_fixed_header_packet_offset += 12;

    	col_append_fstr(pinfo->cinfo, COL_INFO, "CTP Outer: Seq: %5d, Marker, pos: %d,", ctp_outer_fixed_header_sequence_number, ctp_outer_fixed_header_packet_offset);

    	//start a new tvb from our ctp_outer_fixed_header_packet_offset
    	tvbuff_t* tvbuff_ctp_inner = tvb_new_subset_remaining(tvb, ctp_outer_fixed_header_packet_offset);
    	add_new_data_source(pinfo, tvbuff_ctp_inner, "CTP Inner");

    	//parse this as IP/UDP/RTP header again..

    //	fragment_add_check(table, tvb, offset, pinfo, id, data, frag_offset, frag_data_len, more_frags)

    } else {
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


		//22 msb
        { &hf_ctp_outer_fixed_header_timestamp_seconds_pre,					{ "Seconds",			"stltp.ctp_outer.header.timestamp.seconds_pre", 		FT_UINT32, BASE_DEC, NULL, 0xFFFFFC00, NULL, HFILL }},
		//remaining 10 lsb
		{ &hf_ctp_outer_fixed_header_timestamp_a_milliseconds_seconds_pre,	{ "a milliseconds pre",	"stltp.ctp_outer.header.timestamp.a_milliseconds_pre", 	FT_UINT32, BASE_DEC, NULL, 0x000003FF, NULL, HFILL }},

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


    };

    /* Setup protocol subtree array */
    static gint *ett_ptr[] = {
        &ett_main,
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
