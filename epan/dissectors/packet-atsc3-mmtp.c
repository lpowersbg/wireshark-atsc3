/* packet-atsc3-mmtp.c
 * ATSC 3.0
 * MMTP Protocol Instantiation dissector
 * Copyright 2022, Jason Justman <jjustman@ngbp.org>
 *
 * Based off of A/331:2022-03
 *
 * References:
 *
 *	ISO23008-1:2017 MMT
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

void proto_register_atsc3_mmtp(void);
void proto_reg_handoff_atsc3_mmtp(void);

static int proto_atsc3_mmtp = -1;

static int hf_version = -1;
static int hf_packet_counter_flag = -1;
static int hf_fec_type = -1;
static int hf_extension_flag = -1;
static int hf_reserved_1 = -1;
static int hf_qos_classifier_flag = -1;
static int hf_flow_identifier_flag = -1;
static int hf_flow_extension_flag = -1;
static int hf_compression_flag = -1;
static int hf_indiciator_flag = -1;
static int hf_payload_type = -1;
static int hf_packet_id = -1;

static int hf_start_offset = -1;
static int hf_payload = -1;
static int hf_payload_str = -1;


static int ett_main = -1;

static expert_field ei_version1_only = EI_INIT;

static dissector_handle_t xml_handle;
static dissector_handle_t rmt_lct_handle;
static dissector_handle_t rmt_fec_handle;

static gboolean g_codepoint_as_fec_encoding = FALSE;
static gint     g_ext_192                   = LCT_PREFS_EXT_192_FLUTE;
static gint     g_ext_193                   = LCT_PREFS_EXT_193_FLUTE;

/* Code to actually dissect the packets */
/* ==================================== */
static int
dissect_atsc3_mmtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8              version;
    lct_data_exchange_t lct;
    fec_data_exchange_t fec;
    int                 len;

    /* Offset for subpacket dissection */
    guint offset = 0;

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *mmtp_tree;

    tvbuff_t *new_tvb;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATSC3 MMTP");
    col_clear(pinfo->cinfo, COL_INFO);

    /* ALC header dissection */
    /* --------------------- */

    version = (tvb_get_guint8(tvb, offset) >> 6) & 0x03;

    /* Create subtree for the MMTP protocol */
    ti = proto_tree_add_item(tree, proto_atsc3_mmtp, tvb, offset, -1, ENC_NA);
    mmtp_tree = proto_item_add_subtree(ti, ett_main);

    /* Fill the MMTP subtree */
    ti = proto_tree_add_item(mmtp_tree, hf_version, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* This dissector supports only ALCv1 packets.
     * If version > 1 print only version field and quit.
     */
    if (version != 1) {
        expert_add_info(pinfo, ti, &ei_version1_only);

        /* Complete entry in Info column on summary display */
        col_add_fstr(pinfo->cinfo, COL_INFO, "Version: %u (not supported)", version);
        return 0;
    }

    ti = proto_tree_add_item(mmtp_tree, hf_packet_counter_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(mmtp_tree, hf_fec_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(mmtp_tree, hf_extension_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(mmtp_tree, hf_reserved_1, tvb, offset, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(mmtp_tree, hf_qos_classifier_flag, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;


    ti = proto_tree_add_item(mmtp_tree, hf_flow_identifier_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(mmtp_tree, hf_flow_extension_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(mmtp_tree, hf_compression_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(mmtp_tree, hf_indiciator_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(mmtp_tree, hf_payload_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    ti = proto_tree_add_item(mmtp_tree, hf_packet_id, tvb, offset, 2, ENC_BIG_ENDIAN);




//
//    /* LCT header dissection */
//    /* --------------------- */
//    new_tvb = tvb_new_subset_remaining(tvb,offset);
//
//    lct.ext_192 = g_ext_192;
//    lct.ext_193 = g_ext_193;
//    lct.codepoint = 0;
//    lct.is_flute = FALSE;
//    len = call_dissector_with_data(rmt_lct_handle, new_tvb, pinfo, mmtp_tree, &lct);
//    if (len < 0)
//        return offset;
//
//    offset += len;
//
//    /* FEC header dissection */
//    /* --------------------- */
//
//    /* Only if LCT dissector has determined FEC Encoding ID */
//    /* FEC dissector needs to be called with encoding_id filled */
//    if (g_codepoint_as_fec_encoding && tvb_reported_length(tvb) > offset)
//    {
//        fec.encoding_id = lct.codepoint;
//
//        new_tvb = tvb_new_subset_remaining(tvb,offset);
//        len = call_dissector_with_data(rmt_fec_handle, new_tvb, pinfo, mmtp_tree, &fec);
//        if (len < 0)
//            return offset;
//
//        offset += len;
//    } else if(tvb_reported_length(tvb) > offset) {
//    	//use FEC Payload ID as start offset or sbn/esi
//    	//if(lct.codepoint == 128) {
//    	proto_tree_add_item(mmtp_tree, hf_start_offset, tvb, offset,   4, ENC_BIG_ENDIAN);
//
//    	col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "Start Offset: %u", tvb_get_ntohl(tvb, offset));
//
//    	offset += 4;
//    }
//
//    /* Add the Payload item */
//    if (tvb_reported_length(tvb) > offset){
//    	//we have an ext_fdt header (192)
//        if(lct.is_flute){
//            new_tvb = tvb_new_subset_remaining(tvb,offset);
//            call_dissector(xml_handle, new_tvb, pinfo, mmtp_tree);
//        }else{
//        	if(lct.tsi == 0) {
//        		proto_tree_add_item(mmtp_tree, hf_payload_str, tvb, offset, -1, ENC_NA);
//
//        	} else {
//        		proto_tree_add_item(mmtp_tree, hf_payload, tvb, offset, -1, ENC_NA);
//        	}
//        }
//    }

    return tvb_reported_length(tvb);
}

void proto_register_atsc3_mmtp(void)
{
    /* Setup MMT header fields
     * V:2
     * C
     * FEC:2
     * X
     * R
     * Q
     * F
     * E
     * B
     * I
     * type:4
     *
     * packet_id:16
     * */
    static hf_register_info hf_ptr[] = {

        { &hf_version, 				{ "Version", 				"mmtp.version", 				FT_UINT8, BASE_DEC, NULL, 0xC0, NULL, HFILL }},
        { &hf_packet_counter_flag, 	{ "Packet Counter Flag", 	"mmtp.packet_counter_flag", 	FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL }},
        { &hf_fec_type, 			{ "FEC Type", 				"mmtp.fec_type", 				FT_UINT8, BASE_DEC, NULL, 0x18, NULL, HFILL }},
        { &hf_extension_flag, 		{ "Extension Flag", 		"mmtp.extension_flag",			FT_UINT8, BASE_DEC, NULL, 0x04, NULL, HFILL }},
        { &hf_reserved_1, 			{ "Reserved", 				"mmtp.reserved_1",				FT_UINT8, BASE_DEC, NULL, 0x02, NULL, HFILL }},
        { &hf_qos_classifier_flag, 	{ "QoS Classifier Flag", 	"mmtp.qos_classifier_flag", 	FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL }},

        { &hf_flow_identifier_flag, { "Flow Identifier Flag", 	"mmtp.flow_identifier_flag",	FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
        { &hf_flow_extension_flag, 	{ "Flow Extension Flag", 	"mmtp.flow_extension_flag", 	FT_UINT8, BASE_DEC, NULL, 0x40, NULL, HFILL }},
        { &hf_compression_flag, 	{ "Compression Flag", 		"mmtp.compression_flag", 		FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL }},
        { &hf_indiciator_flag, 		{ "Indicator Flag", 		"mmtp.indiciator_flag", 		FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL }},
        { &hf_payload_type, 		{ "Payload Type", 			"mmtp.payload_type",			FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},

        { &hf_packet_id, 			{ "Packet ID", 				"mmtp.packet_id", 				FT_UINT16, BASE_DEC, NULL, 0x0000, NULL, HFILL }},



		{ &hf_start_offset,
		  { "Start Offset", "atsc3-mmtp.start_offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_payload,
          { "Payload", "alc.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_payload_str,
          { "Payload", "alc.payload", FT_STRING, STR_ASCII, NULL, 0x0, NULL, HFILL }}
    };

    /* Setup protocol subtree array */
    static gint *ett_ptr[] = {
        &ett_main,
    };

    static ei_register_info ei[] = {
        { &ei_version1_only, { "mmt.version1_only", PI_PROTOCOL, PI_WARN, "Sorry, this dissector supports MMTP version 1 only", EXPFILL }},
    };

    module_t *module;
    expert_module_t* expert_rmt_alc;

    /* Register the protocol name and description */
    proto_atsc3_mmtp = proto_register_protocol("ATSC 3.0 MMTP", "atsc3-mmtp", "atsc3-mmtp");
    register_dissector("atsc3-mmtp", dissect_atsc3_mmtp, proto_atsc3_mmtp);

    /* Register the header fields and subtrees used */
    proto_register_field_array(proto_atsc3_mmtp, hf_ptr, array_length(hf_ptr));
    proto_register_subtree_array(ett_ptr, array_length(ett_ptr));
    expert_rmt_alc = expert_register_protocol(proto_atsc3_mmtp);
    expert_register_field_array(expert_rmt_alc, ei, array_length(ei));

    /* Register preferences */
    module = prefs_register_protocol(proto_atsc3_mmtp, NULL);

}

void proto_reg_handoff_atsc3_mmtp(void)
{
    dissector_handle_t handle;

    handle = create_dissector_handle(dissect_atsc3_mmtp, proto_atsc3_mmtp);
    dissector_add_for_decode_as_with_preference("udp.port", handle);
    xml_handle = find_dissector_add_dependency("xml", proto_atsc3_mmtp);
//	rmt_lct_handle = find_dissector_add_dependency("atsc3-lct", proto_atsc3_mmtp);
//    rmt_fec_handle = find_dissector_add_dependency("atsc3-fec", proto_atsc3_mmtp);
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
