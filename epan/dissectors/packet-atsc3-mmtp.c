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
static int proto_atsc3_mmtp_mpu = -1;

static int hf_version = -1;
static int hf_packet_counter_flag = -1;
static int hf_fec_type = -1;
static int hf_extension_flag = -1;
static int hf_random_access_point_flag = -1;
static int hf_qos_classifier_flag = -1;
static int hf_flow_identifier_flag = -1;
static int hf_flow_extension_flag = -1;
static int hf_compression_flag = -1;
static int hf_indiciator_flag = -1;
static int hf_payload_type = -1;
static int hf_packet_id = -1;

static int hf_timestamp = -1;
static int hf_packet_sequence_number = -1;
static int hf_packet_counter = -1;

//r, TB, DS, TP, flow_label, extension_header, payload_data
static int hf_reliability_flag = -1; //1 bit
static int hf_type_of_bitrate = -1; //2 bits
static int hf_delay_sensitivity = -1; //3 bits

static int hf_transmission_priority = -1; //3 bits

static int hf_flow_label = -1; // 7 bits
static int hf_extension_header_type = -1;
static int hf_extension_header_length = -1;


//type == 0x0 - MPU
static int hf_mpu_length = -1;
static int hf_mpu_fragment_type = -1;
static int hf_mpu_timed_flag = -1;
static int hf_mpu_fragmentation_indicator = -1;
static int hf_mpu_aggregation_flag = -1;
static int hf_mpu_fragmentation_counter = -1;
static int hf_mpu_sequence_number = -1;

static int hf_mpu_data_unit_length = -1;
static int hf_mpu_data_unit_header = -1;


//type == 0x2 - Signalling Information

static int hf_start_offset = -1;
static int hf_payload = -1;
static int hf_payload_str = -1;


static int ett_main = -1;
static int ett_mmtp_mpu = -1;
static int ett_mmtp_generic_object = -1;
static int ett_mmtp_signalling_message = -1;
static int ett_mmtp_repair_symbol = -1;


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

//    gboolean packet_counter_flag = 0;
//    gboolean extension_flag = 0;
//    gboolean qos_classifier_flag = 0;

    uint packet_counter_flag = 0;
    uint extension_flag = 0;
    uint qos_classifier_flag = 0;

    proto_tree_add_item_ret_uint(mmtp_tree, hf_packet_counter_flag, tvb, offset, 1, ENC_BIG_ENDIAN, &packet_counter_flag);
    proto_tree_add_item(mmtp_tree, hf_fec_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item_ret_uint(mmtp_tree, hf_extension_flag, tvb, offset, 1, ENC_BIG_ENDIAN, &extension_flag);
    proto_tree_add_item(mmtp_tree, hf_random_access_point_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(mmtp_tree, hf_qos_classifier_flag, tvb, offset, 1, ENC_BIG_ENDIAN, &qos_classifier_flag);

    offset++;

    ti = proto_tree_add_item(mmtp_tree, hf_flow_identifier_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(mmtp_tree, hf_flow_extension_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(mmtp_tree, hf_compression_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(mmtp_tree, hf_indiciator_flag, tvb, offset, 1, ENC_BIG_ENDIAN);

    guint32 mmtp_payload_type = -1;

    ti = proto_tree_add_item_ret_uint(mmtp_tree, hf_payload_type, tvb, offset, 1, ENC_BIG_ENDIAN, &mmtp_payload_type);
//    ti = proto_tree_add_item(mmtp_tree, hf_payload_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    //packet_id
    proto_tree_add_item(mmtp_tree, hf_packet_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    //timestamp
    proto_tree_add_item(mmtp_tree, hf_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    //psn
    proto_tree_add_item(mmtp_tree, hf_packet_sequence_number, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    //packet_counter
    if(packet_counter_flag) {
    	proto_tree_add_item(mmtp_tree, hf_packet_counter, tvb, offset, 4, ENC_BIG_ENDIAN);
    	offset+=4;
    }


   proto_tree_add_item(mmtp_tree, hf_reliability_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(mmtp_tree, hf_type_of_bitrate, tvb, offset, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(mmtp_tree, hf_delay_sensitivity, tvb, offset, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(mmtp_tree, hf_transmission_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
   proto_tree_add_item(mmtp_tree, hf_flow_label, tvb, offset, 2, ENC_BIG_ENDIAN);

   offset+=2;

   if(extension_flag) {
    	//todo - parse out
        proto_tree_add_item(mmtp_tree, hf_extension_header_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        proto_tree_add_item(mmtp_tree, hf_extension_header_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        //read varlen extension_header_length

    }



    if(mmtp_payload_type == 0x0) {
        proto_tree *mmtp_mpu_tree;

//        ti = proto_tree_add_item(tree, proto_atsc3_mmtp_mpu, tvb, offset, -1, ENC_NA);

//        proto_tree_add_string(tree, hfindex, tvb, start, length, value)

        mmtp_mpu_tree = proto_tree_add_subtree(mmtp_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_mpu, NULL, "MPU");
        //mmtp_mpu_tree = proto_item_add_subtree(ti, ett_mmtp_mpu);

        //16 bits
        proto_tree_add_item(mmtp_mpu_tree, hf_mpu_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;

        proto_tree_add_item(mmtp_mpu_tree, hf_mpu_fragment_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(mmtp_mpu_tree, hf_mpu_timed_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(mmtp_mpu_tree, hf_mpu_fragmentation_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(mmtp_mpu_tree, hf_mpu_aggregation_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(mmtp_mpu_tree, hf_mpu_fragmentation_counter, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(mmtp_mpu_tree, hf_mpu_sequence_number, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;


    } else if(mmtp_payload_type == 0x2) {
        proto_tree *mmtp_signalling_information_tree;

        mmtp_signalling_information_tree = proto_item_add_subtree(ti, ett_mmtp_signalling_message);

    }




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
     *
     * FT_BOOLEAN
     * */
    static hf_register_info hf_ptr[] = {

        { &hf_version, 								{ "Version", 					"mmtp.version", 					FT_UINT8, BASE_DEC, NULL, 0xC0, NULL, HFILL }},
        { &hf_packet_counter_flag, 					{ "Packet Counter Flag", 		"mmtp.packet_counter_flag", 		FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL }},
        { &hf_fec_type, 							{ "FEC Type", 					"mmtp.fec_type", 					FT_UINT8, BASE_DEC, NULL, 0x18, NULL, HFILL }},
        { &hf_extension_flag, 						{ "Extension Flag", 			"mmtp.extension_flag",				FT_UINT8, BASE_DEC, NULL, 0x04, NULL, HFILL }},
        { &hf_random_access_point_flag, 			{ "Random Access Point Flag", 	"mmtp.random_access_point_flag",	FT_UINT8, BASE_DEC, NULL, 0x02, NULL, HFILL }},
        { &hf_qos_classifier_flag, 					{ "QoS Classifier Flag", 		"mmtp.qos_classifier_flag", 		FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL }},

        { &hf_flow_identifier_flag, 				{ "Flow Identifier Flag", 		"mmtp.flow_identifier_flag",	FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
        { &hf_flow_extension_flag, 					{ "Flow Extension Flag", 		"mmtp.flow_extension_flag", 	FT_UINT8, BASE_DEC, NULL, 0x40, NULL, HFILL }},
        { &hf_compression_flag, 					{ "Compression Flag", 			"mmtp.compression_flag", 		FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL }},
        { &hf_indiciator_flag, 						{ "Indicator Flag", 			"mmtp.indiciator_flag", 		FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL }},
        { &hf_payload_type, 						{ "Payload Type", 				"mmtp.payload_type",			FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},

        { &hf_packet_id, 							{ "Packet ID", 					"mmtp.packet_id", 				FT_UINT16, BASE_DEC, NULL, 0x0000, NULL, HFILL }},


        { &hf_timestamp, 							{ "Packet Timestamp", 			"mmtp.packet_timestamp", 			FT_UINT32, BASE_DEC, NULL, 0x00000000, NULL, HFILL }},
        { &hf_packet_sequence_number, 				{ "Packet Sequence Number", 	"mmtp.packet_sequence_number", 		FT_UINT32, BASE_DEC, NULL, 0x00000000, NULL, HFILL }},
        { &hf_packet_counter, 						{ "Packet Counter", 			"mmtp.packet_counter", 				FT_UINT32, BASE_DEC, NULL, 0x00000000, NULL, HFILL }},

		//build this as uint16, as TP crosses over byte boundary
        { &hf_reliability_flag, 					{ "Reliability Flag", 			"mmtp.reliability_flag", 			FT_UINT16,  BASE_DEC, NULL, 0x8000,   		NULL, HFILL }},
        { &hf_type_of_bitrate, 						{ "Type of Bitrate", 			"mmtp.type_of_bitrate", 			FT_UINT16,  BASE_DEC, NULL, 0x6000,   		NULL, HFILL }},
        { &hf_delay_sensitivity, 					{ "Delay Sensitivity", 			"mmtp.delay_sensitivity", 			FT_UINT16,  BASE_DEC, NULL, 0x1C00,   		NULL, HFILL }},
        { &hf_transmission_priority, 				{ "Transmission Priority", 		"mmtp.transmission_priority", 		FT_UINT16,  BASE_DEC, NULL, 0x0380,  		NULL, HFILL }},
        { &hf_flow_label, 							{ "Flow Label", 				"mmtp.flow_label", 					FT_UINT16,  BASE_DEC, NULL, 0x007F,   		NULL, HFILL }},

		//optional
		{ &hf_extension_header_type, 				{ "Extension Header Type", 		"mmtp.extension_header_type", 		FT_UINT16,  BASE_DEC, NULL, 0x0000,   		NULL, HFILL }},
		{ &hf_extension_header_length, 				{ "Extension Header Length", 	"mmtp.extension_header_length", 	FT_UINT16,  BASE_DEC, NULL, 0x0000,   		NULL, HFILL }},


		//type == 0x0 - MPU

        { &hf_mpu_length, 						{ "DU Length", 					"mmtp.mpu.du_length", 				FT_UINT16, BASE_DEC, NULL, 0x0000, 		NULL, HFILL }},
        { &hf_mpu_fragment_type, 				{ "MPU Fragment Type", 			"mmtp.mpu.fragment_type", 			FT_UINT8,  BASE_DEC, NULL, 0xF0,   		NULL, HFILL }},
        { &hf_mpu_timed_flag, 					{ "Timed Flag", 				"mmtp.mpu.timed_flag", 				FT_UINT8,  BASE_DEC, NULL, 0x08,   		NULL, HFILL }},
        { &hf_mpu_fragmentation_indicator, 		{ "Fragmentation Indicator", 	"mmtp.mpu.fragmentation_indicator",	FT_UINT8,  BASE_DEC, NULL, 0x06,  		NULL, HFILL }},
        { &hf_mpu_aggregation_flag, 			{ "Aggregation Flag", 			"mmtp.mpu.aggregation_flag", 		FT_UINT8,  BASE_DEC, NULL, 0x01,   		NULL, HFILL }},

        { &hf_mpu_fragmentation_counter, 		{ "Fragmentation Counter", 		"mmtp.mpu.fragmentation_counter", 	FT_UINT8,  BASE_DEC, NULL, 0x00,   		NULL, HFILL }},
        { &hf_mpu_sequence_number, 				{ "MPU Sequence Number", 		"mmtp.mpu.sequence_number", 		FT_UINT32, BASE_DEC, NULL, 0x00000000, 	NULL, HFILL }},



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
		&ett_mmtp_mpu,
		&ett_mmtp_generic_object,
		&ett_mmtp_signalling_message,
		&ett_mmtp_repair_symbol
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
