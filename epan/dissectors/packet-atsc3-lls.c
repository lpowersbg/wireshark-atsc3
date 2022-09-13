/* packet-atsc3-lls.c
 * ATSC 3.0
 * ROUTE Protocol Instantiation dissector
 * Copyright 2022, Jason Justman <jjustman@ngbp.org>
 *
 * Based off of A/331:2022-03. Section 6: LOW LEVEL SIGNALING
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

static int proto_atsc3_lls = -1;

static int hf_lls_table_id = -1;
static int hf_lls_group_id = -1;
static int hf_lls_group_count_minus1 = -1;
static int hf_lls_table_version = -1;


static int hf_payload = -1;
static int hf_payload_str = -1;

static int ett_main = -1;

static expert_field ei_payload_decompress_failed = EI_INIT;

static dissector_handle_t xml_handle;
static dissector_handle_t rmt_lct_handle;
static dissector_handle_t rmt_fec_handle;

static dissector_handle_t atsc3_route_dissector_handle;
static dissector_handle_t atsc3_mmtp_dissector_handle;
conversation_t* conv_mmt = NULL;


guint32 has_added_lls_table_slt_version_conversations = 0;


static char* strlcopy(const char* src) {
	int len = strnlen(src, 16384);
	char* dest = (char*)calloc(len+1, sizeof(char));
	return strncpy(dest, src, len);
}


//jjustman-2022-09-12 - hack functions...

static guint32 parseIpAddressIntoIntval(const char* dst_ip_original) {
	if(!dst_ip_original) {
		return 0;
	}
	guint32 ipAddressAsInteger = 0;
	char* dst_ip = strlcopy((char*)dst_ip_original);

	char* pch = strtok (dst_ip,".");
	int offset = 24;

	while (pch != NULL && offset>=0) {
		guint8 octet = atoi(pch);
		ipAddressAsInteger |= octet << offset;
		offset-=8;
		pch = strtok (NULL, " ,.-");
	}
	if(dst_ip) {
		free(dst_ip);
	}
	return ipAddressAsInteger;
}

static guint16 parsePortIntoIntval(const char* dst_port) {
	if(!dst_port) {
		return 0;
	}

	int dst_port_filter_int = atoi(dst_port);
	guint16 dst_port_filter = 0;
	dst_port_filter |= dst_port_filter_int & 0xFFFF;

	return dst_port_filter;
}



static xml_frame_t *__internal_xml_get_first_child_tag(xml_frame_t *frame, const gchar *name)
{
    xml_frame_t *tag = NULL;

    xml_frame_t *xml_item = frame->first_child;
    while (xml_item) {
        if (xml_item->type == XML_FRAME_TAG) {
            if (!name) {  /* get the 1st tag */
                tag = xml_item;
                break;
            } else if (xml_item->name_orig_case && !strcmp(xml_item->name_orig_case, name)) {
                tag = xml_item;
                break;
            }
        }
        xml_item = xml_item->next_sibling;
    }

    return tag;
}


static xml_frame_t *__internal_xml_get_tag(xml_frame_t *frame, const gchar *name)
{
    xml_frame_t *tag = NULL;

    xml_frame_t *xml_item = frame;
    while (xml_item) {
        if (xml_item->type == XML_FRAME_TAG) {
            if (!name) {  /* get the 1st tag */
                tag = xml_item;
                break;
            } else if (xml_item->name_orig_case && !strcmp(xml_item->name_orig_case, name)) {
                tag = xml_item;
                break;
            }
        }
        xml_item = xml_item->next_sibling;
    }

    return tag;
}




/* Code to actually dissect the packets */
/* ==================================== */
static int
dissect_atsc3_lls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	guint32              lls_table_id = -1;
    guint32				lls_table_version = -1;

    int                 len;

    /* Offset for subpacket dissection */
    guint offset = 0;

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *lls_tree;

    xml_frame_t *xml_frame;
    xml_frame_t *xml_dissector_frame;

    int proto_xml = dissector_handle_get_protocol_index(xml_handle);

    tvbuff_t *new_tvb;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATSC3 LLS");
    col_clear(pinfo->cinfo, COL_INFO);


    /* Create subtree for LLS  */
    ti = proto_tree_add_item(tree, proto_atsc3_lls, tvb, offset, -1, ENC_NA);
    lls_tree = proto_item_add_subtree(ti, ett_main);

    /* Fill the LLS subtree */
    lls_table_id = tvb_get_guint8(tvb, offset);


    proto_tree_add_item_ret_uint(lls_tree, hf_lls_table_id, tvb, offset++, 1, ENC_BIG_ENDIAN, &lls_table_id);
    proto_tree_add_item(lls_tree, hf_lls_group_id, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(lls_tree, hf_lls_group_count_minus1, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(lls_tree, hf_lls_table_version, tvb, offset++, 1, ENC_BIG_ENDIAN, &lls_table_version);



	col_append_fstr(pinfo->cinfo, COL_INFO, "%s, version: %d", val_to_str(lls_table_id, atsc3_lls_table_strings, "Unknown lls_table_id: %d"), lls_table_version);

    /* Add the Payload item */
    if (tvb_reported_length(tvb) > offset){


    	if(lls_table_id == 0x01 || lls_table_id==0x02 || lls_table_id == 0x03 || lls_table_id == 0x04) {
    		//uncompress and display

    		//col_append_fstr
    		int gzip_len;
    		tvbuff_t *next_tvb;

    		gzip_len = tvb_captured_length_remaining(tvb, offset);
            next_tvb = tvb_uncompress(tvb, offset, gzip_len);
            if (next_tvb) {
                add_new_data_source(pinfo, next_tvb, "compressed data");
                proto_tree_add_item(lls_tree, hf_payload_str, next_tvb, 0, -1, ENC_STRING);

                if(lls_table_id == 0x01) {
					call_dissector_with_data(xml_handle, next_tvb, pinfo, lls_tree, NULL);

					xml_dissector_frame = (xml_frame_t *)p_get_proto_data(pinfo->pool, pinfo, proto_xml, 0);
					if(xml_dissector_frame == NULL) {
						return tvb_captured_length(tvb);
					} else {

						if(has_added_lls_table_slt_version_conversations != lls_table_version) {
							atsc_lls_slt_add_conversations_from_xml_dissector(xml_dissector_frame);
						}
						has_added_lls_table_slt_version_conversations = lls_table_version;
					}
                } else {
                	call_dissector(xml_handle, next_tvb, pinfo, lls_tree);
                }


            } else {
                expert_add_info(pinfo, ti, &ei_payload_decompress_failed);

            }
            offset += gzip_len;
    	} else {
            proto_tree_add_item(lls_tree, hf_payload, tvb, offset, -1, ENC_NA);
        }
    }

    return tvb_reported_length(tvb);
}

void atsc_lls_slt_add_conversations_from_xml_dissector(xml_frame_t* xml_dissector_frame) {

	//super-hack: TODO: fixme!

	xml_frame_t* slt = xml_dissector_frame->first_child->next_sibling; //xml_get_tag(xml_dissector_frame, "slt");
	xml_frame_t* service = NULL;
	xml_frame_t* broadcastSvcSignaling = NULL;

	if(slt) {

		service = __internal_xml_get_first_child_tag(slt, "Service");

		while(service) {
			broadcastSvcSignaling = __internal_xml_get_first_child_tag(service, "BroadcastSvcSignaling");
			if(broadcastSvcSignaling) {
				xml_frame_t* slsProtocolXml = xml_get_attrib(broadcastSvcSignaling, "slsProtocol");
				xml_frame_t* slsDestinationIpAddressXml = xml_get_attrib(broadcastSvcSignaling, "slsDestinationIpAddress");
				xml_frame_t* slsDestinationUdpPortXml = xml_get_attrib(broadcastSvcSignaling, "slsDestinationUdpPort");
				xml_frame_t* slsSourceIpAddressXml = xml_get_attrib(broadcastSvcSignaling, "slsSourceIpAddress");


				//super hack!
				int slsProtocol = 0;
				guint32 slsDestinationIpAddress = 0;
				guint16 slsDestinationPort = 0;
				guint32 slsSourceIpAddress = 0;

				if(slsProtocolXml) {
					char slsProtocolString[slsProtocolXml->value->length + 1];
					memset(&slsProtocolString, 0, slsProtocolXml->value->length + 1);
					memcpy(&slsProtocolString, slsProtocolXml->value->real_data, slsProtocolXml->value->length);

					slsProtocol = atoi(slsProtocolString);
				}

				if(slsDestinationIpAddressXml) {
					char destIpAddress[slsDestinationIpAddressXml->value->length + 1];
					memset(&destIpAddress, 0, slsDestinationIpAddressXml->value->length + 1);

					memcpy(&destIpAddress, slsDestinationIpAddressXml->value->real_data, slsDestinationIpAddressXml->value->length);
					slsDestinationIpAddress = parseIpAddressIntoIntval(destIpAddress);
				}

				if(slsDestinationUdpPortXml) {
					char destPort[slsDestinationUdpPortXml->value->length + 1];
					memset(&destPort, 0, slsDestinationUdpPortXml->value->length + 1);

					memcpy(&destPort, slsDestinationUdpPortXml->value->real_data, slsDestinationUdpPortXml->value->length);
					slsDestinationPort = parsePortIntoIntval(destPort);
				}

				if(slsSourceIpAddressXml) {
					char sourceIpAddress[slsSourceIpAddressXml->value->length + 1];
					memset(&sourceIpAddress, 0, slsSourceIpAddressXml->value->length + 1);

					memcpy(&sourceIpAddress, slsSourceIpAddressXml->value->real_data, slsSourceIpAddressXml->value->length);
					slsSourceIpAddress = parseIpAddressIntoIntval(sourceIpAddress);
				}

				conversation_t* conv_route = NULL;

				address addr_1;
				guint32 v4_addr_1 = htonl(slsSourceIpAddress);
				set_address(&addr_1, AT_IPv4, 4, &v4_addr_1);

				address addr_2;
				guint32 v4_addr_2 = htonl(slsDestinationIpAddress);
				set_address(&addr_2, AT_IPv4, 4, &v4_addr_2);

				if(slsProtocol == 1) {
					// add ROUTE dissector


					conv_route = conversation_new(1, &addr_2, &addr_1, ENDPOINT_UDP, slsDestinationPort, 0, NO_PORT2);

					conversation_add_proto_data(conv_route,  proto_atsc3_route, NULL);
					conversation_set_dissector(conv_route, atsc3_route_dissector_handle);

				} else if(slsProtocol == 2) {
					//add MMT dissector

					//conv_mmt = conversation_new(1, &addr_1, &addr_2, ENDPOINT_UDP, 0, slsDestinationPort, 0);
					conv_mmt = conversation_new(1, &addr_2, &addr_1, ENDPOINT_UDP, slsDestinationPort, 0, NO_PORT2);


					//conv_mmt = conversation_new(1, &addr_1, &addr_2, ENDPOINT_UDP, 52581, slsDestinationPort, 0);
					//, NO_ADDR2 | NO_PORT2);

					conversation_add_proto_data(conv_mmt,  proto_atsc3_mmtp, NULL);
					conversation_set_dissector(conv_mmt, atsc3_mmtp_dissector_handle);

				}



			}

			service = __internal_xml_get_tag(service->next_sibling, "Service");


		}
	}

}





void proto_register_atsc3_lls(void)
{
    /* Setup ALC header fields */
    static hf_register_info hf_ptr[] = {

        { &hf_lls_table_id,  			{ "LLS Table ID", 			"lls.table_id", 		FT_UINT8, BASE_DEC, atsc3_lls_table_strings, 0x0, NULL, HFILL }},
		{ &hf_lls_group_id, 			{ "LLS Group ID", 			"lls.group_id",			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_lls_group_count_minus1, 	{ "LLS Group Count minus1", "lls.group_count", 		FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_lls_table_version, 		{ "LLS Table Version", 		"lls.table_version", 	FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_payload,      			{ "Payload", "lls.table_payload_bytes", 	FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_payload_str,  			{ "Payload", "lls.table_xml", 				FT_STRING, STR_ASCII, NULL, 0x0, NULL, HFILL }}
    };

    /* Setup protocol subtree array */
    static gint *ett_ptr[] = {
        &ett_main,
    };


    module_t *module;
    expert_module_t* expert_rmt_alc;

    /* Register the protocol name and description */
    proto_atsc3_lls = proto_register_protocol("ATSC 3.0 LLS", "atsc3-lls", "atsc3-lls");
    register_dissector("atsc3-lls", dissect_atsc3_lls, proto_atsc3_lls);

    /* Register the header fields and subtrees used */
    proto_register_field_array(proto_atsc3_lls, hf_ptr, array_length(hf_ptr));
    proto_register_subtree_array(ett_ptr, array_length(ett_ptr));

    static ei_register_info ei[] = {
        { &ei_payload_decompress_failed, { "lls.decompress_failed", PI_PROTOCOL, PI_WARN, "Unable to decompress LLS payload", EXPFILL }},
    };

    expert_rmt_alc = expert_register_protocol(proto_atsc3_lls);
    expert_register_field_array(expert_rmt_alc, ei, array_length(ei));

    /* Register preferences */
    module = prefs_register_protocol(proto_atsc3_lls, NULL);

    prefs_register_obsolete_preference(module, "default.udp_port.enabled");
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

void proto_reg_handoff_atsc3_lls(void)
{
    dissector_handle_t handle;

    handle = create_dissector_handle(dissect_atsc3_lls, proto_atsc3_lls);

    //dissector_add_uint("ip.dst", ATSC3_LLS_IP_ADDRESS_UINT, handle);
    dissector_add_uint("udp.port", ATSC3_LLS_UDP_PORT, handle);


    //    dissector_add_for_decode_as_with_preference("udp.port", handle);
    xml_handle = find_dissector_add_dependency("xml", proto_atsc3_lls);

    atsc3_route_dissector_handle = find_dissector_add_dependency("atsc3-route", proto_atsc3_lls);
    atsc3_mmtp_dissector_handle = find_dissector_add_dependency("atsc3-mmtp", proto_atsc3_lls);


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
