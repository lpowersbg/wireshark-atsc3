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

#include <glib.h>
#include <glibconfig.h>


/* Initialize the protocol and registered fields */
/* ============================================= */

void proto_register_atsc3_mmtp(void);
void proto_reg_handoff_atsc3_mmtp(void);

static int proto_atsc3_mmtp = -1;

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
static int hf_mpu_payload_length = -1;
static int hf_mpu_fragment_type = -1;
static int hf_mpu_timed_flag = -1;
static int hf_mpu_fragmentation_indicator = -1;
static int hf_mpu_aggregation_flag = -1;
static int hf_mpu_fragmentation_counter = -1;
static int hf_mpu_sequence_number = -1;

//a == 1
static int hf_mpu_du_length = -1;
static int hf_mpu_du_header = -1;

//timed == 1
static int hf_mpu_movie_fragment_sequence_number = -1;

static int hf_mpu_sample_number = -1;
static int hf_mpu_offset = -1;
static int hf_mpu_priority = -1;
static int hf_mpu_dep_counter = -1;

//timed == 0
static int hf_mpu_non_timed_item_id = -1;
static int hf_mpu_du = -1;

//end of MPU

//type == 0x2 - Signalling Information
static int hf_si_fragmentation_indicator = -1;
static int hf_si_res_4bits = -1;
static int hf_si_h_length_extension_flag = -1;
static int hf_si_aggregation_flag = -1;
static int hf_si_fragmentation_counter = -1;

static int hf_si_message_length_16 = -1;
static int hf_si_message_length_32 = -1;

static int hf_si_message_id = -1;
static int hf_si_message_version = -1;

//SI message generic table fields
static int 	hf_si_message_table_id = -1;
static guint32 si_message_table_id = 0;

static int hf_si_message_table_version = -1;
static int hf_si_message_table_length_16 = -1;
static int hf_si_message_table_length_32 = -1;

static int hf_si_message_table_reserved_6 = -1;
static int 	hf_si_message_table_mp_table_mode = -1;
static guint32 si_message_table_mp_table_mode = 0;



//mp_table fields
static int hf_si_message_table_mp_table_mmt_package_id_length = -1;
static guint32 si_message_table_mp_table_mmt_package_id_length = 0;

static int hf_si_message_table_mp_table_mmt_package_id_bytes = -1;

static int 	hf_si_message_table_mp_table_mmt_table_descriptors_length = -1;
static guint32 si_message_table_mp_table_mmt_table_descriptors_length = 0;

static int hf_si_message_table_mp_table_mmt_table_descriptors_byte = -1;


static int	hf_si_message_table_mp_table_number_of_assets = -1;
static guint32 si_message_table_mp_table_number_of_assets = -1;

static int hf_si_message_table_identifier_mapping_type = -1;
static guint32 si_message_table_identifier_mapping_type = 0;


//asset_id()
static int hf_si_message_table_identifier_asset_id_type_asset_id_scheme = -1;

static int hf_si_message_table_identifier_asset_id_type_asset_id_length = -1;
static guint32 si_message_table_identifier_asset_id_type_asset_id_length = 0;
static int hf_si_message_table_identifier_asset_id_type_asset_id_bytes = -1;



static int hf_si_message_table_mp_table_asset_type = -1;
static int hf_si_message_table_mp_table_reserved_6 = -1;
static int hf_si_message_table_mp_table_default_asset_flag = -1;
static guint32 si_message_table_mp_table_default_asset_flag = 0;

static int hf_si_message_table_mp_table_asset_clock_relation_flag = -1;
static guint32 si_message_table_mp_table_asset_clock_relation_flag = 0;


static int hf_si_message_table_mp_table_asset_clock_relation_id = -1;
static int hf_si_message_table_mp_table_asset_clock_relation_reserved_7 = -1;


static int hf_si_message_table_mp_table_asset_clock_relation_asset_timescale_flag = -1;
static guint32 si_message_table_mp_table_asset_clock_relation_asset_timescale_flag = 0;

static int hf_si_message_table_mp_table_asset_clock_relation_asset_timescale = -1;

static int hf_si_message_table_mp_table_asset_location_count = -1;
static guint32 si_message_table_mp_table_asset_location_count = 0;

static int hf_si_message_table_mmt_general_location_info_location_type = -1;
static guint32 si_message_table_mmt_general_location_info_location_type = 0;

static int hf_si_message_table_mmt_general_location_info_packet_id = -1;

static int hf_si_message_table_mp_table_asset_descriptors_length = -1;
static guint32 si_message_table_mp_table_asset_descriptors_length = 0;

static int hf_si_message_table_mp_table_asset_descriptors_bytes = -1;

//descriptor
static int	 hf_si_message_descriptor_tag = -1;
static guint32 si_message_descriptor_tag = 0;

static int	 hf_si_message_descriptor_length = -1;
static guint32 si_message_descriptor_length = 0;

//0x0001 - mpu_timestamp_descriptor N ~= si_message_descriptor_length/12
static int hf_si_message_descriptor_mpu_timestamp_descriptor_mpu_sequence_number = -1;
static int hf_si_message_descriptor_mpu_timestamp_descriptor_mpu_presentation_time = -1;







//end mp_table fields


//mmt_atsc3_message fields
static int hf_si_mmt_atsc3_message_service_id = -1;
static int hf_si_mmt_atsc3_message_content_type = -1;
static int hf_si_mmt_atsc3_message_content_version = -1;
static int hf_si_mmt_atsc3_message_content_compression = -1;

static int hf_si_mmt_atsc3_message_URI_length = -1;
static int hf_si_mmt_atsc3_message_URI_bytes = -1;

static int hf_si_mmt_atsc3_message_content_length = -1;
static int hf_si_mmt_atsc3_message_content_bytes = -1;
static int hf_si_mmt_atsc3_message_content_bytes_str = -1;

//mmt_atsc3_message descriptor generic fields
static int  hf_si_mmt_atsc3_message_content_descriptor_tag = -1;
static guint32 hf_si_mmt_atsc3_message_content_descriptor_length = 0;

static int 	hf_si_mmt_atsc3_message_content_descriptor_number_of_assets = -1;
static guint32 si_mmt_atsc3_message_content_descriptor_number_of_assets = 0;

static int 	hf_si_mmt_atsc3_message_content_descriptor_asset_id_length = -1;
static guint32 si_mmt_atsc3_message_content_descriptor_asset_id_length = 0;

static int hf_si_mmt_atsc3_message_content_descriptor_asset_id_bytes = -1;

//vspd

static int hf_si_mmt_atsc3_message_descriptor_vspd_codec_code = -1;

static int 	hf_si_mmt_atsc3_message_descriptor_vspd_temporal_scalability_present= -1;
static guint32 si_mmt_atsc3_message_descriptor_vspd_temporal_scalability_present = 0;

static int 	hf_si_mmt_atsc3_message_descriptor_vspd_scalability_info_present = -1;
static guint32 si_mmt_atsc3_message_descriptor_vspd_scalability_info_present = 0;

static int 	hf_si_mmt_atsc3_message_descriptor_vspd_multiview_info_present = -1;
static guint32 si_mmt_atsc3_message_descriptor_vspd_multiview_info_present = 0;

static int 	hf_si_mmt_atsc3_message_descriptor_vspd_res_cf_bd_info_present = -1;
static guint32 si_mmt_atsc3_message_descriptor_vspd_res_cf_bd_info_present = 0;

static int 	hf_si_mmt_atsc3_message_descriptor_vspd_pr_info_present = -1;
static guint32 si_mmt_atsc3_message_descriptor_vspd_pr_info_present = 0;

static int 	hf_si_mmt_atsc3_message_descriptor_vspd_br_info_present = -1;
static guint32 si_mmt_atsc3_message_descriptor_vspd_br_info_present = 0;

static int 	hf_si_mmt_atsc3_message_descriptor_vspd_color_info_present = -1;
static guint32 si_mmt_atsc3_message_descriptor_vspd_color_info_present = 0;

static int	hf_si_mmt_atsc3_message_descriptor_vspd_reserved_1 = -1;
static guint32 si_mmt_atsc3_message_descriptor_vspd_reserved_1 = 0;


// cad

static int	hf_si_mmt_atsc3_message_descriptor_cad_language_length = -1;
static guint32 si_mmt_atsc3_message_descriptor_cad_language_length = 0;

static int	hf_si_mmt_atsc3_message_descriptor_cad_language_byte = -1;

static int hf_si_mmt_atsc3_message_descriptor_cad_role = -1;
static int hf_si_mmt_atsc3_message_descriptor_cad_aspect_ratio = -1;
static int hf_si_mmt_atsc3_message_descriptor_cad_easy_reader = -1;
static int hf_si_mmt_atsc3_message_descriptor_cad_profile = -1;
static int hf_si_mmt_atsc3_message_descriptor_cad_3d_support = -1;
static int hf_si_mmt_atsc3_message_descriptor_cad_reserved_4 = -1;

//aspd

static int hf_si_mmt_atsc3_message_descriptor_aspd_codec_code = -1;

//metadata intailsh f_si_mmt_atsc3_message_descriptor_aspd_num_presentations
//
static int  hf_si_mmt_atsc3_message_descriptor_aspd_num_presentations = -1;
static guint32 si_mmt_atsc3_message_descriptor_aspd_num_presentations = 0;


static int  hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_present = -1;
static guint32 si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_present = 0;

static int hf_si_mmt_atsc3_message_descriptor_aspd_emergency_info_time_present = -1;
static guint32 si_mmt_atsc3_message_descriptor_aspd_emergency_info_time_present = 0;

static int hf_si_mmt_atsc3_message_descriptor_aspd_reserved_6 = -1;


static int hf_si_mmt_atsc3_message_descriptor_aspd_presentation_id = -1;

static int  hf_si_mmt_atsc3_message_descriptor_aspd_interactivity_enabled = -1;
static guint32 si_mmt_atsc3_message_descriptor_aspd_interactivity_enabled = 0;

static int  hf_si_mmt_atsc3_message_descriptor_aspd_profile_channel_config_present = -1;
static guint32 si_mmt_atsc3_message_descriptor_aspd_profile_channel_config_present = 0;

static int  hf_si_mmt_atsc3_message_descriptor_aspd_profile_long = -1;
static guint32 si_mmt_atsc3_message_descriptor_aspd_profile_long = 0;

static int  hf_si_mmt_atsc3_message_descriptor_aspd_channel_config_long = -1;
static guint32 si_mmt_atsc3_message_descriptor_aspd_channel_config_long = 0;

static int  hf_si_mmt_atsc3_message_descriptor_aspd_audio_renderering_info_present = -1;
static guint32 si_mmt_atsc3_message_descriptor_aspd_audio_renderering_info_present = 0;

static int 	hf_si_mmt_atsc3_message_descriptor_aspd_language_present = -1;
static guint32 si_mmt_atsc3_message_descriptor_aspd_language_present = 0;

static int 	hf_si_mmt_atsc3_message_descriptor_aspd_accessibility_role_present = -1;
static guint32 si_mmt_atsc3_message_descriptor_aspd_accessibility_role_present = 0;

static int 	hf_si_mmt_atsc3_message_descriptor_aspd_label_present = -1;
static guint32 si_mmt_atsc3_message_descriptor_aspd_label_present = 0;


static int hf_si_mmt_atsc3_message_descriptor_aspd_profile_level_indiciation_long = -1;
static int hf_si_mmt_atsc3_message_descriptor_aspd_profile_level_indiciation = -1;
static int hf_si_mmt_atsc3_message_descriptor_aspd_audio_channel_config_long = -1;
static int hf_si_mmt_atsc3_message_descriptor_aspd_audio_channel_config = -1;
static int hf_si_mmt_atsc3_message_descriptor_aspd_audio_renderering_indiciation = -1;

static int 	hf_si_mmt_atsc3_message_descriptor_aspd_num_languages_minus_1 = -1;
static guint32 si_mmt_atsc3_message_descriptor_aspd_num_languages_minus_1 = 0;

static int 	hf_si_mmt_atsc3_message_descriptor_aspd_language_length = -1;
static guint32 si_mmt_atsc3_message_descriptor_aspd_language_length = 0;

static int hf_si_mmt_atsc3_message_descriptor_aspd_language_bytes = -1;


static int hf_si_mmt_atsc3_message_descriptor_aspd_accessibility = -1;
static int hf_si_mmt_atsc3_message_descriptor_aspd_role = -1;

static int  hf_si_mmt_atsc3_message_descriptor_aspd_label_length = -1;
static guint32 si_mmt_atsc3_message_descriptor_aspd_label_length = 0;

static int hf_si_mmt_atsc3_message_descriptor_aspd_label_data_bytes = -1;


static int 	hf_si_mmt_atsc3_message_descriptor_aspd_presentation_aux_stream_num_presentation_aux_streams = -1;
static guint32 si_mmt_atsc3_message_descriptor_aspd_presentation_aux_stream_num_presentation_aux_streams = 0;

static int hf_si_mmt_atsc3_message_descriptor_aspd_presentation_aux_stream_id = -1;

//multi_stream_info()
static int 	hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_this_is_main_stream = -1;
static guint32 si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_this_is_main_stream = 0;

static int hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_this_stream_id = -1;

static int hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_reserved_1 = -1;
static int hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_bundle_id = -1;

static int hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_reserved_1_main_stream = -1;

static int hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_num_auxiliary_streams = -1;
static guint32 si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_num_auxiliary_streams = 0;

static int hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_delivery_method = -1;
static int hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_auxiliary_stream_id = -1;

//emergency_information_time_info()
static int hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_start_time_present = -1;
static guint32 si_mmt_atsc3_message_descriptor_aspd_emergency_information_start_time_present = 0;

static int hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_end_time_present = -1;
static guint32 si_mmt_atsc3_message_descriptor_aspd_emergency_information_end_time_present = 0;

static int hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_reserved_6 = -1;

static int hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_start_time = -1;
static int hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_start_time_reserved_6 = -1;
static int hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_start_time_ms = -1;

static int hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_end_time = -1;
static int hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_end_time_reserved_6 = -1;
static int hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_end_time_ms = -1;


//hrbm

static int hf_si_hrbm_message_max_buffer_size = -1;
static int hf_si_hrbm_message_fixed_end_to_end_delay = -1;
static int hf_si_hrbm_message_max_transmission_delay = -1;


//hrbm_removal
static int	hf_si_hrbm_removal_message_number_of_operation_modes = -1;
static guint32 si_hrbm_removal_message_number_of_operation_modes = 0;

static int hf_si_hrbm_removal_message_data_removal_type = -1;
static int hf_si_hrbm_removal_message_max_decapsulation_buffer_size = -1;
static int hf_si_hrbm_removal_message_buffer_management_valid = -1;
static int hf_si_hrbm_removal_message_reserved_7 = -1;




//
static int hf_start_offset = -1;
static int hf_payload = -1;
static int hf_payload_str = -1;


static int ett_main = -1;
static int ett_mmtp_mpu = -1;
static int ett_mmtp_generic_object = -1;
static int ett_mmtp_signalling_message = -1;

static int ett_mmtp_signalling_message_pa_message = -1;

static int ett_mmtp_signalling_message_mpi_message_subset = -1;
static int ett_mmtp_signalling_message_mpi_message_complete = -1;

static int ett_mmtp_signalling_message_mpt_message_subset = -1;
static int ett_mmtp_signalling_message_mpt_message_complete = -1;

static int ett_mmtp_signalling_message_mmt_atsc3_message_vspd = -1;
static int ett_mmtp_signalling_message_mmt_atsc3_message_cad = -1;
static int ett_mmtp_signalling_message_mmt_atsc3_message_aspd = -1;

static int ett_mmtp_signalling_message_cri_message = -1;
static int ett_mmtp_signalling_message_dci_message  = -1;
static int ett_mmtp_signalling_message_sswr_message = -1;
static int ett_mmtp_signalling_message_al_fec_message = -1;
static int ett_mmtp_signalling_message_hrbm_message = -1;
static int ett_mmtp_signalling_message_mc_message = -1;
static int ett_mmtp_signalling_message_ac_message = -1;
static int ett_mmtp_signalling_message_af_message = -1;
static int ett_mmtp_signalling_message_rqf_message = -1;
static int ett_mmtp_signalling_message_adc_message = -1;
static int ett_mmtp_signalling_message_hrbm_removal_message = -1;
static int ett_mmtp_signalling_message_ls_message = -1;
static int ett_mmtp_signalling_message_lr_message = -1;
static int ett_mmtp_signalling_message_namf_message = -1;
static int ett_mmtp_signalling_message_ldc_message = -1;

static int ett_mmtp_repair_symbol = -1;


static expert_field ei_version1_only = EI_INIT;
static expert_field ei_payload_decompress_failed = EI_INIT;
static expert_field ei_atsc3_mmt_atsc3_message_content_type_unknown = EI_INIT;

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

    guint32 packet_counter_flag = 0;
    guint32 extension_flag = 0;
    guint32 qos_classifier_flag = 0;

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

    guint32 mmtp_packet_id = -1;
    //packet_id
    proto_tree_add_item_ret_uint(mmtp_tree, hf_packet_id, tvb, offset, 2, ENC_BIG_ENDIAN, &mmtp_packet_id);
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

        guint32 mpu_sequence_number = -1;
        guint32 mpu_fragment_type = -1;
        guint32 mpu_timed_flag = -1;
        guint32 mpu_aggregation_flag = -1;


//        ti = proto_tree_add_item(tree, proto_atsc3_mmtp_mpu, tvb, offset, -1, ENC_NA);

//        proto_tree_add_string(tree, hfindex, tvb, start, length, value)

        mmtp_mpu_tree = proto_tree_add_subtree(mmtp_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_mpu, NULL, "MPU");
        //mmtp_mpu_tree = proto_item_add_subtree(ti, ett_mmtp_mpu);

        //16 bits
        proto_tree_add_item(mmtp_mpu_tree, hf_mpu_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;

        proto_tree_add_item_ret_uint(mmtp_mpu_tree, hf_mpu_fragment_type, tvb, offset, 1, ENC_BIG_ENDIAN, &mpu_fragment_type);
        proto_tree_add_item_ret_uint(mmtp_mpu_tree, hf_mpu_timed_flag, tvb, offset, 1, ENC_BIG_ENDIAN, &mpu_timed_flag);
        proto_tree_add_item(mmtp_mpu_tree, hf_mpu_fragmentation_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item_ret_uint(mmtp_mpu_tree, hf_mpu_aggregation_flag, tvb, offset, 1, ENC_BIG_ENDIAN, &mpu_aggregation_flag);
        offset++;

        proto_tree_add_item(mmtp_mpu_tree, hf_mpu_fragmentation_counter, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item_ret_uint(mmtp_mpu_tree, hf_mpu_sequence_number, tvb, offset, 4, ENC_BIG_ENDIAN, &mpu_sequence_number);
        offset+=4;

        //if mpu_aggregation_flag == 1, read du_length and du_header
        if(mpu_aggregation_flag) {
            proto_tree_add_item(mmtp_mpu_tree, hf_mpu_du_length, tvb, offset, 2, ENC_BIG_ENDIAN);
            //mpu_du_header is a varlen...
        }

    	col_append_fstr(pinfo->cinfo, COL_INFO, "packet_id: %d, mpu_seq: %d, %s", mmtp_packet_id, mpu_sequence_number, val_to_str(mpu_fragment_type, atsc3_mmtp_mpu_fragment_type_isobmff_box_name, "RSVD: %d"));

    	if(mpu_timed_flag) {
    		//movie fragment seq num, sample num, offset, priority, dep_counter

    		guint32 mfu_sample_number = -1;
			guint32 mfu_sample_offset = -1;

	        proto_tree_add_item(mmtp_mpu_tree, hf_mpu_movie_fragment_sequence_number, tvb, offset, 4, ENC_BIG_ENDIAN);
	        offset+=4;

	        proto_tree_add_item_ret_uint(mmtp_mpu_tree, hf_mpu_sample_number, tvb, offset, 4, ENC_BIG_ENDIAN, &mfu_sample_number);
	        offset+=4;

	        proto_tree_add_item_ret_uint(mmtp_mpu_tree, hf_mpu_offset, tvb, offset, 4, ENC_BIG_ENDIAN, &mfu_sample_offset);
	        offset+=4;

	        proto_tree_add_item(mmtp_mpu_tree, hf_mpu_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
	        offset++;
	        proto_tree_add_item(mmtp_mpu_tree, hf_mpu_dep_counter, tvb, offset, 1, ENC_BIG_ENDIAN);
	        offset++;

	    	col_append_fstr(pinfo->cinfo, COL_INFO, " sample: %d, offset: %d", mfu_sample_number, mfu_sample_offset);

	        proto_tree_add_item(mmtp_mpu_tree, hf_mpu_du, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);

    	} else {
    		//item_id
	        proto_tree_add_item(mmtp_mpu_tree, hf_mpu_non_timed_item_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	        offset+=4;
    	}


    } else if(mmtp_payload_type == 0x2) {
        proto_tree *mmtp_signalling_information_tree;

		guint32 si_header_len_extension = -1;
		guint32 si_aggregation_flag = -1;
		guint32 si_message_length = -1;

        mmtp_signalling_information_tree = proto_tree_add_subtree(mmtp_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message, NULL, "SI");


        proto_tree_add_item(mmtp_signalling_information_tree, hf_si_fragmentation_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(mmtp_signalling_information_tree, hf_si_res_4bits, tvb, offset, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item_ret_uint(mmtp_signalling_information_tree, hf_si_h_length_extension_flag, tvb, offset, 1, ENC_BIG_ENDIAN, &si_header_len_extension);
        proto_tree_add_item_ret_uint(mmtp_signalling_information_tree, hf_si_aggregation_flag, tvb, offset, 1, ENC_BIG_ENDIAN, &si_aggregation_flag);

        offset++;

        proto_tree_add_item(mmtp_signalling_information_tree, hf_si_fragmentation_counter, tvb, offset, 1, ENC_BIG_ENDIAN);

        offset++;

        if(si_aggregation_flag) {
			if(si_header_len_extension) {
				proto_tree_add_item_ret_uint(mmtp_signalling_information_tree, hf_si_message_length_32, tvb, offset, 4, ENC_BIG_ENDIAN, &si_message_length);
				offset+=4;

			} else {
				proto_tree_add_item_ret_uint(mmtp_signalling_information_tree, hf_si_message_length_16, tvb, offset, 2, ENC_BIG_ENDIAN, &si_message_length);
				offset+=2;
			}
        } else {
        	//otherwise, single shot signalling_information message

    		guint32 si_message_id = -1;
    		guint32 si_message_version = -1;

            proto_tree_add_item_ret_uint(mmtp_signalling_information_tree, hf_si_message_id, tvb, offset, 2, ENC_BIG_ENDIAN, &si_message_id);
			offset+=2;

			proto_tree_add_item_ret_uint(mmtp_signalling_information_tree, hf_si_message_version, tvb, offset, 1, ENC_BIG_ENDIAN, &si_message_version);
            offset++;

            if(si_message_id != PA_message && si_message_id != MPI_message && si_message_id != MMT_ATSC3_MESSAGE_ID && si_message_id != SIGNED_MMT_ATSC3_MESSAGE_ID) {
				proto_tree_add_item_ret_uint(mmtp_signalling_information_tree, hf_si_message_length_16, tvb, offset, 2, ENC_BIG_ENDIAN, &si_message_length);
				offset+=2;
            } else {
            	proto_tree_add_item_ret_uint(mmtp_signalling_information_tree, hf_si_message_length_32, tvb, offset, 4, ENC_BIG_ENDIAN, &si_message_length);
            	offset+=4;
            }


        	col_append_fstr(pinfo->cinfo, COL_INFO, "%s (0x%04x): packet_id: %5d, si_message_version: %3d",
        			val_to_str(si_message_id, atsc3_mmtp_si_message_type_strings, "si unknown"), si_message_id, mmtp_packet_id, si_message_version);

            //extension

            //payload

        	switch (si_message_id) {

        		//PA_message
        		case PA_message:
        		{
					proto_tree* pa_message_tree = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_pa_message, NULL, "PA Message");

        			break;
        		}

        		case MPI_message_start:
        		case MPI_message_start + 0x01:
        		case MPI_message_start + 0x02:
        		case MPI_message_start + 0x03:
        		case MPI_message_start + 0x04:
        		case MPI_message_start + 0x05:
        		case MPI_message_start + 0x06:
        		case MPI_message_start + 0x07:
        		case MPI_message_start + 0x08:
        		case MPI_message_start + 0x09:
        		case MPI_message_start + 0x0A:
        		case MPI_message_start + 0x0B:
        		case MPI_message_start + 0x0C:
        		case MPI_message_start + 0x0D:
        		case MPI_message_start + 0x0E:
				{

					proto_tree* mpi_subset = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_mpi_message_subset, NULL, "MPI - Subset");
					break;

				}

        		case MPI_message_end:
        		{
					proto_tree* mpi_complete = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_mpi_message_complete, NULL, "MPI - Complete");

        			break;
        		}

        		//mpt messages

				case MPT_message_start:
				case MPT_message_start + 0x01:
				case MPT_message_start + 0x02:
				case MPT_message_start + 0x03:
				case MPT_message_start + 0x04:
				case MPT_message_start + 0x05:
				case MPT_message_start + 0x06:
				case MPT_message_start + 0x07:
				case MPT_message_start + 0x08:
				case MPT_message_start + 0x09:
				case MPT_message_start + 0x0A:
				case MPT_message_start + 0x0B:
				case MPT_message_start + 0x0C:
				case MPT_message_start + 0x0D:
				case MPT_message_start + 0x0E:
				{
					proto_tree* mpt_partial_tree = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_mpt_message_subset, NULL, "MP Table - Subset");

					offset = atsc3_mmtp_mp_table_decode(tvb, offset, pinfo, mpt_partial_tree);

					break;
				}

				//full mpt message
				case MPT_message_end: {

					proto_tree* mpt_complete_tree = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_mpt_message_complete, NULL, "MP Table - Complete");
					offset = atsc3_mmtp_mp_table_decode(tvb, offset, pinfo, mpt_complete_tree);

					break;
				}

				//cri
				case CRI_message: {

					proto_tree* cri_tree = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_cri_message, NULL, "CRI Message");

					break;
				}

				//jjustman-2022-09-22 - todo: additional mmt SI message types here...

				case DCI_message: {

					proto_tree* dci_tree = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_dci_message, NULL, "DCI Message");

					break;
				}

				case SSWR_message: {

					proto_tree* sswr_tree = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_sswr_message, NULL, "SSWR Message");

					break;
				}


				case AL_FEC_message: {

					proto_tree* al_fec_tree = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_al_fec_message, NULL, "AL-FEC Message");

					break;
				}

				case HRBM_message: {

					proto_tree* hrbm_tree = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_hrbm_message, NULL, "HRBM Message");

					//hrbm field attributes

					proto_tree_add_item(hrbm_tree, hf_si_hrbm_message_max_buffer_size, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(hrbm_tree, hf_si_hrbm_message_fixed_end_to_end_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(hrbm_tree, hf_si_hrbm_message_max_transmission_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;


					break;
				}

				case MC_message: {

					proto_tree* mc_tree = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_mc_message, NULL, "MC Message");

					break;
				}
				case AC_message: {

					proto_tree* ac_tree = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_ac_message, NULL, "AC Message");

					break;
				}
				case AF_message: {

					proto_tree* af_tree = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_af_message, NULL, "AF Message");

					break;
				}
				case RQF_message: {

					proto_tree* rqf_tree = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_rqf_message, NULL, "RQF Message");

					break;
				}
				case ADC_message: {

					proto_tree* adc_tree = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_adc_message, NULL, "ADC Message");

					break;
				}

				case HRB_removal_message: {

					proto_tree* hrbm_removal_tree = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_ls_message, NULL, "HRBM Removal Message");


					proto_tree* hrbm_tree = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_hrbm_message, NULL, "HRBM Message");

					//hrbm_removal field attributes

					proto_tree_add_item_ret_uint(hrbm_tree, hf_si_hrbm_removal_message_number_of_operation_modes, tvb, offset, 1, ENC_BIG_ENDIAN, &si_hrbm_removal_message_number_of_operation_modes);
					offset++;
					for(guint32 i=0; i < si_hrbm_removal_message_number_of_operation_modes; i++) {
						proto_tree_add_item(hrbm_tree, hf_si_hrbm_removal_message_data_removal_type, tvb, offset, 1, ENC_BIG_ENDIAN);
						offset++;
						proto_tree_add_item(hrbm_tree, hf_si_hrbm_removal_message_max_decapsulation_buffer_size, tvb, offset, 4, ENC_BIG_ENDIAN);
						offset += 4;
					}
					proto_tree_add_item(hrbm_tree, hf_si_hrbm_removal_message_buffer_management_valid, tvb, offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(hrbm_tree, hf_si_hrbm_removal_message_reserved_7, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset++;
					break;
				}

				case LS_message: {

					proto_tree* ls_tree = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_ls_message, NULL, "LS Message");

					break;
				}
				case LR_message: {

					proto_tree* lr_tree = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_lr_message, NULL, "LR Message");

					break;
				}
				case NAMF_message: {

					proto_tree* namf_tree = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_namf_message, NULL, "NAMF Message");

					break;
				}
				case LDC_message: {

					proto_tree* ldc_message = proto_tree_add_subtree(mmtp_signalling_information_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_ldc_message, NULL, "LDC Message");

					break;
				}




        		case MMT_ATSC3_MESSAGE_ID:
        		{

					guint32 si_message_mmt_atsc3_message_service_id = -1;
					guint32 si_message_mmt_atsc3_message_content_type = -1;
					guint32 si_message_mmt_atsc3_message_content_version = -1;
					guint32 si_message_mmt_atsc3_message_content_compression = -1;

					proto_tree_add_item_ret_uint(mmtp_signalling_information_tree, hf_si_mmt_atsc3_message_service_id, tvb, offset, 2, ENC_BIG_ENDIAN, &si_message_mmt_atsc3_message_service_id);
					offset+=2;

					proto_tree_add_item_ret_uint(mmtp_signalling_information_tree, hf_si_mmt_atsc3_message_content_type, tvb, offset, 2, ENC_BIG_ENDIAN, &si_message_mmt_atsc3_message_content_type);
					offset+=2;

					proto_tree_add_item_ret_uint(mmtp_signalling_information_tree, hf_si_mmt_atsc3_message_content_version, tvb, offset, 1, ENC_BIG_ENDIAN, &si_message_mmt_atsc3_message_content_version);
					offset++;

					proto_tree_add_item_ret_uint(mmtp_signalling_information_tree, hf_si_mmt_atsc3_message_content_compression, tvb, offset, 1, ENC_BIG_ENDIAN, &si_message_mmt_atsc3_message_content_compression);
					offset++;


					//uri
					guint32 si_message_mmt_atsc3_message_URI_length = -1;
					proto_tree_add_item_ret_uint(mmtp_signalling_information_tree, hf_si_mmt_atsc3_message_URI_length, tvb, offset, 1, ENC_BIG_ENDIAN, &si_message_mmt_atsc3_message_URI_length);
					offset++;

					if(si_message_mmt_atsc3_message_URI_length) {
	//encoding, scope, retval, lenretval);
						proto_tree_add_item(mmtp_signalling_information_tree, hf_si_mmt_atsc3_message_URI_bytes, tvb, offset, si_message_mmt_atsc3_message_URI_length, ENC_UTF_8);
						offset+=si_message_mmt_atsc3_message_URI_length;

					}
					//message content length/bytes
					guint32 si_message_mmt_atsc3_message_content_length = -1;

					proto_tree_add_item_ret_uint(mmtp_signalling_information_tree, hf_si_mmt_atsc3_message_content_length, tvb, offset, 4, ENC_BIG_ENDIAN, &si_message_mmt_atsc3_message_URI_length);

					offset+=4;

					if(si_message_mmt_atsc3_message_content_compression == 2) {
						int gzip_len;
			    		tvbuff_t *next_tvb = NULL;

						gzip_len = tvb_captured_length_remaining(tvb, offset);
						next_tvb = tvb_uncompress(tvb, offset, gzip_len);
						if (next_tvb) {
							add_new_data_source(pinfo, next_tvb, "compressed data");
							proto_tree_add_item(mmtp_signalling_information_tree, hf_si_mmt_atsc3_message_content_bytes_str, next_tvb, 0, -1, ENC_STRING);

							atsc3_mmt_atsc3_message_decode(next_tvb, pinfo, mmtp_signalling_information_tree, si_message_mmt_atsc3_message_service_id, si_message_mmt_atsc3_message_content_type);

						} else {
							expert_add_info(pinfo, ti, &ei_payload_decompress_failed);

						}
						offset += gzip_len;
					} else {
						//TODO: __MIN(tvb_captured_length_remaining(tvb, offset), si_message_mmt_atsc3_message_content_length
						//proto_tree_add_item(mmtp_signalling_information_tree, hf_si_mmt_atsc3_message_content_bytes, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_BIG_ENDIAN);
						atsc3_mmt_atsc3_message_decode(tvb, pinfo, mmtp_signalling_information_tree, si_message_mmt_atsc3_message_service_id, si_message_mmt_atsc3_message_content_type);

					}

					col_append_fstr(pinfo->cinfo, COL_INFO, ", mmt_atsc3_message type: %s (0x%04x), service: %d, version: %d",
							val_to_str(si_message_mmt_atsc3_message_content_type, atsc3_mmtp_si_message_mmt_atsc3_message_type_strings, "mmt_atsc3_message type unknown"),
							si_message_mmt_atsc3_message_content_type,
							si_message_mmt_atsc3_message_service_id,
							si_message_mmt_atsc3_message_content_version);

					//any interior mmt_atsc3_message parsing should use next_tvb

					break;
        		}
        	}
//					break;
//
//        	default:
//

        //	}
        }
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


guint atsc3_mmt_descriptor_decode(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree) {

	proto_tree* descriptor_tree = proto_tree_add_subtree(tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_mpt_message_complete, NULL, "Descriptor");

	proto_tree_add_item_ret_uint(descriptor_tree, hf_si_message_descriptor_tag, tvb, offset, 2, ENC_BIG_ENDIAN, &si_message_descriptor_tag);
	offset += 2;

	proto_tree_add_item_ret_uint(descriptor_tree, hf_si_message_descriptor_length, tvb, offset, 1, ENC_BIG_ENDIAN, &si_message_descriptor_length);
	offset++;

	if(si_message_descriptor_tag == MMT_MPU_TIMESTAMP_DESCRIPTOR) {
		for(guint32 m=0; m < si_message_descriptor_length / 12; m++) {
			proto_tree_add_item(descriptor_tree, hf_si_message_descriptor_mpu_timestamp_descriptor_mpu_sequence_number, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(descriptor_tree, hf_si_message_descriptor_mpu_timestamp_descriptor_mpu_presentation_time, tvb, offset, 8, ENC_BIG_ENDIAN);
			offset += 8;
		}
	} else {
		//jjustman-2022-09-12 - TODO
	}




	return offset;
}


guint atsc3_mmtp_mp_table_decode(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *mpt_tree) {


	proto_tree_add_item_ret_uint(mpt_tree, hf_si_message_table_id, tvb, offset, 1, ENC_BIG_ENDIAN, &si_message_table_id);
	offset++;
	proto_tree_add_item(mpt_tree, hf_si_message_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(mpt_tree, hf_si_message_table_length_16, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	//reserved_6
	proto_tree_add_item(mpt_tree, hf_si_message_table_reserved_6, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_uint(mpt_tree, hf_si_message_table_mp_table_mode, tvb, offset, 1, ENC_BIG_ENDIAN, &si_message_table_mp_table_mode);
	offset++;

	//for refactoring...

	if(si_message_table_id == 0x20 || si_message_table_id == 0x11 ) {
		//mmt_package_id
		proto_tree_add_item_ret_uint(mpt_tree, hf_si_message_table_mp_table_mmt_package_id_length, tvb, offset, 1, ENC_BIG_ENDIAN, &si_message_table_mp_table_mmt_package_id_length);
		offset++;
		proto_tree_add_item(mpt_tree, hf_si_message_table_mp_table_mmt_package_id_bytes, tvb, offset, si_message_table_mp_table_mmt_package_id_length, ENC_NA);
		offset += si_message_table_mp_table_mmt_package_id_length;


		//mmt_table_descriptors
		proto_tree_add_item_ret_uint(mpt_tree, hf_si_message_table_mp_table_mmt_table_descriptors_length, tvb, offset, 1, ENC_BIG_ENDIAN, &si_message_table_mp_table_mmt_table_descriptors_length);
		offset += 2;
		proto_tree_add_item(mpt_tree, hf_si_message_table_mp_table_mmt_table_descriptors_byte, tvb, offset, si_message_table_mp_table_mmt_table_descriptors_length, ENC_NA);
		offset += si_message_table_mp_table_mmt_table_descriptors_length;
	}

	proto_tree_add_item_ret_uint(mpt_tree, hf_si_message_table_mp_table_number_of_assets, tvb, offset, 1, ENC_BIG_ENDIAN, &si_message_table_mp_table_number_of_assets);
	offset++;

	for(guint32 i=0; i < si_message_table_mp_table_number_of_assets; i++) {
		//todo: refactor identifier_mapping(...);
		proto_tree_add_item_ret_uint(mpt_tree, hf_si_message_table_identifier_mapping_type, tvb, offset, 1, ENC_BIG_ENDIAN, &si_message_table_identifier_mapping_type);
		offset++;
		if(si_message_table_identifier_mapping_type == 0x00) {
			//asset_id()
			proto_tree_add_item(mpt_tree, hf_si_message_table_identifier_asset_id_type_asset_id_scheme, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item_ret_uint(mpt_tree, hf_si_message_table_identifier_asset_id_type_asset_id_length, tvb, offset, 4, ENC_BIG_ENDIAN, &si_message_table_identifier_asset_id_type_asset_id_length);
			offset += 4;

			proto_tree_add_item(mpt_tree, hf_si_message_table_identifier_asset_id_type_asset_id_bytes, tvb, offset, si_message_table_identifier_asset_id_type_asset_id_length, ENC_NA);

			offset += si_message_table_identifier_asset_id_type_asset_id_length;


		} else if(FALSE) {
			//
		}

		proto_tree_add_item(mpt_tree, hf_si_message_table_mp_table_asset_type, tvb, offset, 4, ENC_UTF_8);
		offset += 4;

		proto_tree_add_item(mpt_tree, hf_si_message_table_mp_table_reserved_6, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item_ret_uint(mpt_tree, hf_si_message_table_mp_table_default_asset_flag, tvb, offset, 1, ENC_BIG_ENDIAN, &si_message_table_mp_table_default_asset_flag);
		proto_tree_add_item_ret_uint(mpt_tree, hf_si_message_table_mp_table_asset_clock_relation_flag, tvb, offset, 1, ENC_BIG_ENDIAN, &si_message_table_mp_table_asset_clock_relation_flag);
		offset++;

		if(si_message_table_mp_table_asset_clock_relation_flag) {
			proto_tree_add_item(mpt_tree, hf_si_message_table_mp_table_asset_clock_relation_id, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			proto_tree_add_item(mpt_tree, hf_si_message_table_mp_table_asset_clock_relation_reserved_7, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item_ret_uint(mpt_tree, hf_si_message_table_mp_table_asset_clock_relation_asset_timescale_flag, tvb, offset, 1, ENC_BIG_ENDIAN, &si_message_table_mp_table_asset_clock_relation_asset_timescale_flag);
			offset++;

			if(si_message_table_mp_table_asset_clock_relation_asset_timescale_flag) {
				proto_tree_add_item(mpt_tree, hf_si_message_table_mp_table_asset_clock_relation_asset_timescale, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
		}

		//asset location
		proto_tree_add_item_ret_uint(mpt_tree, hf_si_message_table_mp_table_asset_location_count, tvb, offset, 1, ENC_BIG_ENDIAN, &si_message_table_mp_table_asset_location_count);
		offset++;

		for(guint32 j=0; j < si_message_table_mp_table_asset_location_count; j++) {
			//MMT_general_location_info();
			//todo - refactor me out
			proto_tree_add_item_ret_uint(mpt_tree, hf_si_message_table_mmt_general_location_info_location_type, tvb, offset, 1, ENC_BIG_ENDIAN, &si_message_table_mmt_general_location_info_location_type);
			offset++;

			if(si_message_table_mmt_general_location_info_location_type == 0x00) {
				proto_tree_add_item(mpt_tree, hf_si_message_table_mmt_general_location_info_packet_id, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;

			} else {
				//jjustman-2022-09-12 - todo
			}

		}


		//asset descriptors
		proto_tree_add_item_ret_uint(mpt_tree, hf_si_message_table_mp_table_asset_descriptors_length, tvb, offset, 2, ENC_BIG_ENDIAN, &si_message_table_mp_table_asset_descriptors_length);
		offset += 2;

		proto_tree_add_item(mpt_tree, hf_si_message_table_mp_table_asset_descriptors_bytes, tvb, offset, si_message_table_mp_table_asset_descriptors_length, ENC_NA);

		//parse out our descriptor tags...
		guint32 last_offset = offset;
		while(si_message_table_mp_table_asset_descriptors_length) {
			offset = atsc3_mmt_descriptor_decode(tvb, offset, pinfo, mpt_tree);
			si_message_table_mp_table_asset_descriptors_length -= (offset - last_offset);
		}
	}

	return offset;
}


guint atsc3_mmt_atsc3_message_descriptor_header_decode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

	guint offset = 0;

	//jjustman-2022-09-09 - todo - fix me
	proto_item* tag_item = proto_tree_add_item(tree, hf_si_mmt_atsc3_message_content_descriptor_tag, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	proto_tree_add_item(tree, hf_si_mmt_atsc3_message_content_descriptor_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	proto_tree_add_item_ret_uint(tree, hf_si_mmt_atsc3_message_content_descriptor_number_of_assets, tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_content_descriptor_number_of_assets);

	offset++;

	for(guint32 i=0; i < si_mmt_atsc3_message_content_descriptor_number_of_assets; i++) {
		proto_tree_add_item_ret_uint(tree, hf_si_mmt_atsc3_message_content_descriptor_asset_id_length, tvb, offset, 4, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_content_descriptor_asset_id_length); //ENC_UTF_8);
		offset+=4;

		proto_tree_add_item(tree, hf_si_mmt_atsc3_message_content_descriptor_asset_id_bytes, tvb, offset, si_mmt_atsc3_message_content_descriptor_asset_id_length, ENC_NA); //ENC_UTF_8);

		offset+=si_mmt_atsc3_message_content_descriptor_asset_id_length;
	}

	return offset;
}



//mmtp.si.message_id == 33024
guint atsc3_mmt_atsc3_message_decode(tvbuff_t* tvb, packet_info *pinfo, proto_tree *tree, guint32 si_message_mmt_atsc3_message_service_id, guint32 si_message_mmt_atsc3_message_content_type) {

	guint offset = 0;



	switch (si_message_mmt_atsc3_message_content_type) {

		case MMT_ATSC3_MESSAGE_CONTENT_TYPE_UserServiceDescription:

			call_dissector(xml_handle, tvb, pinfo, tree);

			break;

		case MMT_ATSC3_MESSAGE_CONTENT_TYPE_MPD_FROM_DASHIF:

			//noimpl for now
			break;


		case MMT_ATSC3_MESSAGE_CONTENT_TYPE_HELD:

			call_dissector(xml_handle, tvb, pinfo, tree);

			break;

		case MMT_ATSC3_MESSAGE_CONTENT_TYPE_VIDEO_STREAM_PROPERTIES_DESCRIPTOR:
		{
			proto_tree* vspd = proto_tree_add_subtree(tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_mmt_atsc3_message_vspd, NULL, "Video Stream Properties Descriptor");
			offset += atsc3_mmt_atsc3_message_descriptor_header_decode(tvb, pinfo, vspd);

			proto_tree_add_item(vspd, hf_si_mmt_atsc3_message_descriptor_vspd_codec_code, tvb, offset, 4, ENC_BIG_ENDIAN);
	        offset += 4;

			proto_tree_add_item_ret_uint(vspd, hf_si_mmt_atsc3_message_descriptor_vspd_temporal_scalability_present,	tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_vspd_temporal_scalability_present);
			proto_tree_add_item_ret_uint(vspd, hf_si_mmt_atsc3_message_descriptor_vspd_scalability_info_present,	 	tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_vspd_scalability_info_present);
			proto_tree_add_item_ret_uint(vspd, hf_si_mmt_atsc3_message_descriptor_vspd_multiview_info_present, 			tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_vspd_multiview_info_present);
			proto_tree_add_item_ret_uint(vspd, hf_si_mmt_atsc3_message_descriptor_vspd_res_cf_bd_info_present, 			tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_vspd_res_cf_bd_info_present);
			proto_tree_add_item_ret_uint(vspd, hf_si_mmt_atsc3_message_descriptor_vspd_pr_info_present, 				tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_vspd_pr_info_present);
			proto_tree_add_item_ret_uint(vspd, hf_si_mmt_atsc3_message_descriptor_vspd_br_info_present, 				tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_vspd_br_info_present);
			proto_tree_add_item_ret_uint(vspd, hf_si_mmt_atsc3_message_descriptor_vspd_color_info_present, 				tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_vspd_color_info_present);
			proto_tree_add_item_ret_uint(vspd, hf_si_mmt_atsc3_message_descriptor_vspd_reserved_1, 						tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_vspd_reserved_1);

			offset++;

			//if(...present) { }



			break;
		}

		case MMT_ATSC3_MESSAGE_CONTENT_TYPE_CAPTION_ASSET_DESCRIPTOR:
		{
			proto_tree* cad = proto_tree_add_subtree(tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_mmt_atsc3_message_cad, NULL, "Caption Asset Descriptor");
//			offset += atsc3_mmt_atsc3_message_descriptor_header_decode(tvb, pinfo, cad);
			proto_item* tag_item = proto_tree_add_item(cad, hf_si_mmt_atsc3_message_content_descriptor_tag, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			proto_tree_add_item(cad, hf_si_mmt_atsc3_message_content_descriptor_length, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			proto_tree_add_item_ret_uint(cad, hf_si_mmt_atsc3_message_content_descriptor_number_of_assets, tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_content_descriptor_number_of_assets);

			offset++;

			for(guint32 i=0; i < si_mmt_atsc3_message_content_descriptor_number_of_assets; i++) {
				proto_tree_add_item_ret_uint(cad, hf_si_mmt_atsc3_message_content_descriptor_asset_id_length, tvb, offset, 4, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_content_descriptor_asset_id_length);
				offset+=4;

				proto_tree_add_item(cad, hf_si_mmt_atsc3_message_content_descriptor_asset_id_bytes, tvb, offset, si_mmt_atsc3_message_content_descriptor_asset_id_length, ENC_NA);

				offset += si_mmt_atsc3_message_content_descriptor_asset_id_length;

				//language_length
				proto_tree_add_item_ret_uint(cad, hf_si_mmt_atsc3_message_descriptor_cad_language_length, tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_cad_language_length);
				offset++;

				//lanauge_bytes
				proto_tree_add_item(cad, hf_si_mmt_atsc3_message_descriptor_cad_language_byte, tvb, offset, si_mmt_atsc3_message_descriptor_cad_language_length, ENC_UTF_8);
				offset += si_mmt_atsc3_message_descriptor_cad_language_length;


				//role
				proto_tree_add_item(cad, hf_si_mmt_atsc3_message_descriptor_cad_role, 			tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(cad, hf_si_mmt_atsc3_message_descriptor_cad_aspect_ratio,	tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;

				proto_tree_add_item(cad, hf_si_mmt_atsc3_message_descriptor_cad_easy_reader, 	tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(cad, hf_si_mmt_atsc3_message_descriptor_cad_profile, 		tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(cad, hf_si_mmt_atsc3_message_descriptor_cad_3d_support, 	tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(cad, hf_si_mmt_atsc3_message_descriptor_cad_reserved_4, 	tvb, offset, 1, ENC_BIG_ENDIAN);

				offset++;
			}


			//reserved payload...ignore

			break;
		}


		case MMT_ATSC3_MESSAGE_CONTENT_TYPE_AUDIO_STREAM_PROPERTIES_DESCRIPTOR:
		{
			proto_tree* aspd = proto_tree_add_subtree(tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_mmtp_signalling_message_mmt_atsc3_message_aspd, NULL, "Audio Stream Properties Descriptor");
			offset += atsc3_mmt_atsc3_message_descriptor_header_decode(tvb, pinfo, aspd);

			proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_codec_code, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			//num_presentations

			proto_tree_add_item_ret_uint(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_num_presentations,				tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_aspd_num_presentations);
			offset++;

			proto_tree_add_item_ret_uint(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_present,	 	tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_present);
			proto_tree_add_item_ret_uint(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_emergency_info_time_present, 	tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_aspd_emergency_info_time_present);
			proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_reserved_6, tvb, offset, 1, ENC_BIG_ENDIAN); //ENC_UTF_8);
			offset++;

			for(guint32 j=0; j < si_mmt_atsc3_message_descriptor_aspd_num_presentations; j++) {
				proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_presentation_id, tvb, offset, 1, ENC_BIG_ENDIAN); //ENC_UTF_8);
				offset++;

				proto_tree_add_item_ret_uint(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_interactivity_enabled,		 	tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_aspd_interactivity_enabled);
				proto_tree_add_item_ret_uint(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_profile_channel_config_present, 	tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_aspd_profile_channel_config_present);
				proto_tree_add_item_ret_uint(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_profile_long,				 	tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_aspd_profile_long);
				proto_tree_add_item_ret_uint(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_channel_config_long,	 			tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_aspd_channel_config_long);
				proto_tree_add_item_ret_uint(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_audio_renderering_info_present,	tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_aspd_audio_renderering_info_present);
				proto_tree_add_item_ret_uint(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_language_present,	 			tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_aspd_language_present);
				proto_tree_add_item_ret_uint(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_accessibility_role_present,	 	tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_aspd_accessibility_role_present);
				proto_tree_add_item_ret_uint(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_label_present,	 				tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_aspd_label_present);

				offset++;

				if(si_mmt_atsc3_message_descriptor_aspd_profile_channel_config_present) {

					if(si_mmt_atsc3_message_descriptor_aspd_profile_long == 1) {
						//3*8 - AC4

						proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_profile_level_indiciation_long, tvb, offset, 3, ENC_BIG_ENDIAN);

						offset+=3;
					} else {
						//8 - MPEG-H
						proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_profile_level_indiciation, tvb, offset, 1, ENC_BIG_ENDIAN);

						offset++;
					}

					if(si_mmt_atsc3_message_descriptor_aspd_channel_config_long) {
						//3*8
						proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_audio_channel_config_long, tvb, offset, 3, ENC_BIG_ENDIAN);

						offset+=3;

					} else {
						//8
						proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_audio_channel_config, tvb, offset, 3, ENC_BIG_ENDIAN);

						offset++;
					}
				}

				if(si_mmt_atsc3_message_descriptor_aspd_audio_renderering_info_present) {
					//audio_renderering_indication
					proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_audio_renderering_indiciation, tvb, offset, 1, ENC_BIG_ENDIAN);

					offset++;
				}

				if(si_mmt_atsc3_message_descriptor_aspd_language_present) {
					proto_tree_add_item_ret_uint(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_num_languages_minus_1, tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_aspd_num_languages_minus_1);
					offset++;
					for(guint32 k=0; k < si_mmt_atsc3_message_descriptor_aspd_num_languages_minus_1 + 1; k++) {
						proto_tree_add_item_ret_uint(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_language_length, tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_aspd_language_length);
						offset++;

						proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_language_bytes, tvb, offset, si_mmt_atsc3_message_descriptor_aspd_language_length, ENC_UTF_8);

						offset += si_mmt_atsc3_message_descriptor_aspd_language_length;
					}
				}

				if(si_mmt_atsc3_message_descriptor_aspd_accessibility_role_present) {
					///todo: spec query, as num_languages_minus_1 is only defined under language-present
					for(guint32 k=0; k < si_mmt_atsc3_message_descriptor_aspd_num_languages_minus_1 + 1; k++) {
						proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_accessibility, tvb, offset, 1, ENC_BIG_ENDIAN);
						offset++;
					}
					proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_role, tvb, offset, 1, ENC_BIG_ENDIAN);
				}


				if(si_mmt_atsc3_message_descriptor_aspd_label_present) {
					proto_tree_add_item_ret_uint(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_label_length, tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_aspd_label_length);
					offset++;

					proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_label_data_bytes, tvb, offset, si_mmt_atsc3_message_descriptor_aspd_label_length, ENC_UTF_8);
					offset += si_mmt_atsc3_message_descriptor_aspd_label_length;

				}

				if(si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_present) {

					//presentation_aux_stream_info()
					proto_tree_add_item_ret_uint(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_presentation_aux_stream_num_presentation_aux_streams, tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_aspd_presentation_aux_stream_num_presentation_aux_streams);
					offset++;
					for(guint32 m=0; m < si_mmt_atsc3_message_descriptor_aspd_presentation_aux_stream_num_presentation_aux_streams; m++) {
						proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_presentation_aux_stream_id, tvb, offset, 1, ENC_BIG_ENDIAN);
						offset++;
					}
				}
			}

			if(si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_present) {
				//multi_stream_info()
				proto_tree_add_item_ret_uint(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_this_is_main_stream, tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_this_is_main_stream);
				proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_this_stream_id, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;

				proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_reserved_1, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_bundle_id, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;

				if(si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_this_is_main_stream) {
					proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_reserved_1_main_stream, tvb, offset, 1, ENC_UTF_8);
					proto_tree_add_item_ret_uint(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_num_auxiliary_streams, tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_num_auxiliary_streams);
					offset++;

					for(guint32 m=0; m < si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_num_auxiliary_streams; m++) {
						proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_delivery_method, tvb, offset, 1, ENC_BIG_ENDIAN);
						proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_auxiliary_stream_id, tvb, offset, 1, ENC_BIG_ENDIAN);
						offset++;
					}
				}
			}

			if(si_mmt_atsc3_message_descriptor_aspd_emergency_info_time_present) {

				proto_tree_add_item_ret_uint(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_start_time_present, tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_aspd_emergency_information_start_time_present);
				proto_tree_add_item_ret_uint(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_end_time_present, tvb, offset, 1, ENC_BIG_ENDIAN, &si_mmt_atsc3_message_descriptor_aspd_emergency_information_end_time_present);
				proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_reserved_6, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;

				if(si_mmt_atsc3_message_descriptor_aspd_emergency_information_start_time_present) {

					proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_start_time, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset+=4;
					proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_start_time_reserved_6, tvb, offset, 2, ENC_BIG_ENDIAN);
					proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_start_time_ms, tvb, offset, 2, ENC_BIG_ENDIAN);
					offset+=2;
				}

				if(si_mmt_atsc3_message_descriptor_aspd_emergency_information_end_time_present) {

					proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_end_time, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset+=4;
					proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_end_time_reserved_6, tvb, offset, 2, ENC_BIG_ENDIAN);
					proto_tree_add_item(aspd, hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_end_time_ms, tvb, offset, 2, ENC_BIG_ENDIAN);
					offset+=2;
				}
			}


			break;
		}


		default: {
			expert_add_info(pinfo, tree, &ei_atsc3_mmt_atsc3_message_content_type_unknown);

		}


	}

	return 0;
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

        { &hf_flow_identifier_flag, 				{ "Flow Identifier Flag", 		"mmtp.flow_identifier_flag",	FT_UINT8, BASE_DEC, NULL, 						0x80, NULL, HFILL }},
        { &hf_flow_extension_flag, 					{ "Flow Extension Flag", 		"mmtp.flow_extension_flag", 	FT_UINT8, BASE_DEC, NULL, 						0x40, NULL, HFILL }},
        { &hf_compression_flag, 					{ "Compression Flag", 			"mmtp.compression_flag", 		FT_UINT8, BASE_DEC, NULL, 						0x20, NULL, HFILL }},
        { &hf_indiciator_flag, 						{ "Indicator Flag", 			"mmtp.indiciator_flag", 		FT_UINT8, BASE_DEC, NULL, 						0x10, NULL, HFILL }},
        { &hf_payload_type, 						{ "Payload Type", 				"mmtp.payload_type",			FT_UINT8, BASE_DEC, atsc3_mmtp_payload_type, 	0x0F, NULL, HFILL }},

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

        { &hf_mpu_payload_length, 					{ "MPU Payload Length", 			"mmtp.mpu.payload_length", 					FT_UINT16, BASE_DEC, NULL, 									0x0000, 		NULL, HFILL }},
        { &hf_mpu_fragment_type, 					{ "MPU Fragment Type", 				"mmtp.mpu.fragment_type", 					FT_UINT8,  BASE_DEC, atsc3_mmtp_mpu_fragment_type, 			0xF0,   		NULL, HFILL }},
        { &hf_mpu_timed_flag, 						{ "Timed Flag", 					"mmtp.mpu.timed_flag", 						FT_UINT8,  BASE_DEC, NULL, 									0x08,   		NULL, HFILL }},
        { &hf_mpu_fragmentation_indicator, 			{ "Fragmentation Indicator", 		"mmtp.mpu.fragmentation_indicator",			FT_UINT8,  BASE_DEC, atsc3_mmtp_mpu_fragmentation_indiciator, 							0x06,  			NULL, HFILL }},
        { &hf_mpu_aggregation_flag, 				{ "Aggregation Flag", 				"mmtp.mpu.aggregation_flag", 				FT_UINT8,  BASE_DEC, NULL, 									0x01,   		NULL, HFILL }},

        { &hf_mpu_fragmentation_counter, 			{ "Fragmentation Counter", 			"mmtp.mpu.fragmentation_counter", 			FT_UINT8,  BASE_DEC, NULL, 									0x00,   		NULL, HFILL }},
        { &hf_mpu_sequence_number, 					{ "MPU Sequence Number", 			"mmtp.mpu.sequence_number", 				FT_UINT32, BASE_DEC, NULL, 									0x00000000, 	NULL, HFILL }},

		//only if mpu_aggregation_flag == 1
        { &hf_mpu_du_length, 						{ "MMTP MPU DU Length", 			"mmtp.mpu.du.length", 						FT_UINT16, BASE_DEC, NULL, 									0x0000, 		NULL, HFILL }},
        { &hf_mpu_du_header, 						{ "MMTP MPU Header", 				"mmtp.mpu.du.header", 						FT_UINT16, BASE_DEC, NULL, 									0x0000, 		NULL, HFILL }},

		//for mpu_timed_flag == 1
        { &hf_mpu_movie_fragment_sequence_number, 	{ "Movie Fragment Sequence Number", "mmtp.mpu.movie_fragment_sequence_number", 	FT_UINT32, BASE_DEC, NULL, 									0x0000, 		NULL, HFILL }},
        { &hf_mpu_sample_number, 					{ "Sample Number", 					"mmtp.mpu.sample_number", 					FT_UINT32, BASE_DEC, NULL, 									0x0000, 		NULL, HFILL }},
        { &hf_mpu_offset, 							{ "Offset", 						"mmtp.mpu.offset", 							FT_UINT32, BASE_DEC, NULL, 									0x0000, 		NULL, HFILL }},
        { &hf_mpu_priority, 						{ "Subsample Priority", 			"mmtp.mpu.priority", 						FT_UINT8, BASE_DEC, NULL, 									0x0000, 		NULL, HFILL }},
        { &hf_mpu_dep_counter, 						{ "Dependency Counter", 			"mmtp.mpu.dep_counter", 					FT_UINT8, BASE_DEC, NULL, 									0x0000, 		NULL, HFILL }},

		//for mpu_timed_flag == 0
        { &hf_mpu_non_timed_item_id, 				{ "Non-timed Item ID", 				"mmtp.mpu.item_id", 						FT_UINT32, BASE_DEC, NULL, 									0x0000, 		NULL, HFILL }},

		//DU payload
        { &hf_mpu_du, 								{ "DU", 							"mmtp.mpu.du", 								FT_NONE, BASE_NONE, NULL, 									0x0000, 		NULL, HFILL }},

		//////
		//mmtp_payload_type == 0x2

        { &hf_si_fragmentation_indicator, 			{ "Fragmentation Indicator", 		"mmtp.si.fragmentation_indicator",			FT_UINT8,  BASE_DEC, atsc3_mmtp_si_fragmentation_indiciator, 	0xC0,  			NULL, HFILL }},
        { &hf_si_res_4bits, 						{ "Reserved (0000)", 				"mmtp.si.reserved_4bits",					FT_UINT8,  BASE_DEC, NULL,									 	0x3C,  			NULL, HFILL }},
        { &hf_si_h_length_extension_flag, 			{ "H Len Extension Flag",			"mmtp.si.h_length_extension_flag",			FT_UINT8,  BASE_DEC, NULL,									 	0x02,  			NULL, HFILL }},
        { &hf_si_aggregation_flag, 					{ "Aggregation Flag", 				"mmtp.si.aggregation_flag",					FT_UINT8,  BASE_DEC, NULL,									 	0x01,  			NULL, HFILL }},

        { &hf_si_fragmentation_counter, 			{ "Fragmentation Counter", 			"mmtp.si.fragmentation_counter", 			FT_UINT8,  BASE_DEC, NULL, 										0x00,   		NULL, HFILL }},

        { &hf_si_message_length_16,		 			{ "Message Length (16b)", 			"mmtp.si.message.length",		 			FT_UINT16,  BASE_DEC, NULL, 									0x00,   		NULL, HFILL }},
        { &hf_si_message_length_32,		 			{ "Message Length (32b)", 			"mmtp.si.message_length",		 			FT_UINT32,  BASE_DEC, NULL, 									0x00,   		NULL, HFILL }},


		//signalling message general format

        { &hf_si_message_id,		 				{ "Signalling Message ID", 			"mmtp.si.message_id",		 				FT_UINT16, BASE_DEC, atsc3_mmtp_si_message_type_strings,		0x00,   		NULL, HFILL }},
        { &hf_si_message_version,		 			{ "Signalling Message Version", 	"mmtp.si.message_version",		 			FT_UINT8,  BASE_DEC, NULL, 										0x00,   		NULL, HFILL }},


		//mmt si message table generic header
        { &hf_si_message_table_id,		 			{ "Signalling Message Table ID", 			"mmtp.si.message.table.id",		 		FT_UINT8,  BASE_DEC, NULL, 										0x00,   		NULL, HFILL }},
        { &hf_si_message_table_version,		 		{ "Signalling Message Table Version", 		"mmtp.si.message.table.versionid",		FT_UINT8,  BASE_DEC, NULL, 										0x00,   		NULL, HFILL }},
	    { &hf_si_message_table_length_16,		 	{ "Signalling Message Table Length", 		"mmtp.si.message.table.length",			FT_UINT16,  BASE_DEC, NULL, 									0x00,   		NULL, HFILL }},
	    { &hf_si_message_table_length_32,		 	{ "Signalling Message Table Length", 		"mmtp.si.message.table.length",			FT_UINT32,  BASE_DEC, NULL, 									0x00,   		NULL, HFILL }},

		{ &hf_si_message_table_reserved_6,		 	{ "Signalling Message Table reserved_6",	"mmtp.si.message.table.reserved_6",		FT_UINT8,  BASE_DEC, NULL, 										0xFC,   		NULL, HFILL }},
	    { &hf_si_message_table_mp_table_mode,		{ "Signalling Message Table mp_table_mode",	"mmtp.si.message.table.mp_table_mode",	FT_UINT8,  BASE_DEC, NULL, 										0x03,   		NULL, HFILL }},

		//mmt package_id
	    { &hf_si_message_table_mp_table_mmt_package_id_length,		{ "MMT Package ID Length",	"mmtp.si.message.mp_table.mmt_package_id_length",	FT_UINT8,  BASE_DEC, NULL, 							0x00,   		NULL, HFILL }},
	    { &hf_si_message_table_mp_table_mmt_package_id_bytes,		{ "MMT Package ID Bytes",	"mmtp.si.message.mp_table.mmt_package_id_length",	FT_BYTES,  BASE_NONE, NULL, 						0x00,   		NULL, HFILL }},


		//mmt table_descriptors
		{ &hf_si_message_table_mp_table_mmt_table_descriptors_length,	{ "MP Table Descriptors Length",	"mmtp.si.message.mp_table.mp_table_descriptors_length",	FT_UINT16,  BASE_DEC, NULL, 							0x00,   		NULL, HFILL }},
		{ &hf_si_message_table_mp_table_mmt_table_descriptors_byte,		{ "MP Table Descriptors Bytes",	"mmtp.si.message.mp_table.mp_table_descriptors_bytes",	FT_BYTES,  BASE_NONE, NULL, 						0x00,   		NULL, HFILL }},


		//number of assets
		{ &hf_si_message_table_mp_table_number_of_assets,			{ "Number of Assets",	"mmtp.si.message.mp_table.number_of_assets",					FT_UINT8,  BASE_DEC, NULL, 		0x00,   		NULL, HFILL }},


		{ &hf_si_message_table_mp_table_asset_type,					{ "Asset Type",	"mmtp.si.message.mp_table.asset_type",									FT_STRING,  STR_ASCII, NULL,	0x00,   		NULL, HFILL }},
		{ &hf_si_message_table_mp_table_reserved_6,					{ "Reserved_6",		"mmtp.si.message.mp_table.reserved_6",								FT_UINT8, 	BASE_DEC, NULL, 	0xFC,   		NULL, HFILL }},
		{ &hf_si_message_table_mp_table_default_asset_flag,			{ "Default Asset Flag",	"mmtp.si.message.mp_table.default_asset_flag",					FT_UINT8, 	BASE_DEC, NULL, 	0x02,   		NULL, HFILL }},
		{ &hf_si_message_table_mp_table_asset_clock_relation_flag,	{ "Asset Clock Relation Flag",	"mmtp.si.message.mp_table.asset_clock_relation_flag",	FT_UINT8,  	BASE_DEC, NULL, 	0x01,   		NULL, HFILL }},

		// if si_message_table_mp_table_asset_clock_relation_flag
		{ &hf_si_message_table_mp_table_asset_clock_relation_id,					{ "Asset Clock Relation ID",	"mmtp.si.message.mp_table.asset_clock.relation_id",				FT_UINT8,  BASE_DEC, NULL, 		0x00,   		NULL, HFILL }},
		{ &hf_si_message_table_mp_table_asset_clock_relation_reserved_7,			{ "reserved_7",					"mmtp.si.message.mp_table.asset_clock.reserved_7",				FT_UINT8,  BASE_DEC, NULL, 		0xFE,   		NULL, HFILL }},
		{ &hf_si_message_table_mp_table_asset_clock_relation_asset_timescale_flag,	{ "Asset Timescale Flag",		"mmtp.si.message.mp_table.asset_clock.asset_timescale_flag",	FT_UINT8,  BASE_DEC, NULL, 		0x01,   		NULL, HFILL }},

		//if si_message_table_mp_table_asset_clock_relation_asset_timescale_flag
		{ &hf_si_message_table_mp_table_asset_clock_relation_asset_timescale,		{ "Asset Timescale",		"mmtp.si.message.mp_table.asset_clock.asset_timescale_flag",	FT_UINT32,  BASE_DEC, NULL, 		0x00000000,   		NULL, HFILL }},


		//asset location

		{ &hf_si_message_table_mp_table_asset_location_count,			{ "Asset Location Count",		"mmtp.si.message.mp_table.asset_location.count",	FT_UINT8,  BASE_DEC, NULL, 		0x0,   		NULL, HFILL }},

		//mmt_general_location_info() {
		{ &hf_si_message_table_mmt_general_location_info_location_type,	{ "Location Type",				"mmtp.si.message.location_info.location_type",		FT_UINT8,  BASE_DEC, atsc3_mmtp_signalling_information_location_type_mapping, 		0x0,   		NULL, HFILL }},
		//if (si_message_table_mmt_general_location_info_location_type == 0x00)
		{ &hf_si_message_table_mmt_general_location_info_packet_id,		{ "Packet ID",					"mmtp.si.message.location_info.packet_id",		FT_UINT16,  BASE_DEC, NULL, 		0x0,   		NULL, HFILL }},
		//TODO: other location_info values to impl...

		//} //mmt_general_location_info


		//identifier_mapping types

		{ &hf_si_message_table_identifier_mapping_type,				{ "Identifier Mapping Type",	"mmtp.si.message.identifier_mapping_type",					FT_UINT8,  BASE_DEC, atsc3_mmtp_signalling_information_identifier_type_mapping,	0x00,   		NULL, HFILL }},

		//asset_id() type
		{ &hf_si_message_table_identifier_asset_id_type_asset_id_scheme,	{ "Asset ID Scheme",	"mmtp.si.message.asset_id.scheme",			FT_UINT32,  BASE_DEC, NULL,	0x00000000,   		NULL, HFILL }},
		{ &hf_si_message_table_identifier_asset_id_type_asset_id_length,	{ "Asset ID Length",	"mmtp.si.message.asset_id.length",			FT_UINT32,  BASE_DEC, NULL,	0x00000000,   		NULL, HFILL }},
		{ &hf_si_message_table_identifier_asset_id_type_asset_id_bytes,		{ "Asset ID Bytes",		"mmtp.si.message.asset_id.bytes",			FT_BYTES,  BASE_NONE, NULL,	0x00,   		NULL, HFILL }},




		//asset_descriptors
		{ &hf_si_message_table_mp_table_asset_descriptors_length,	{ "Asset Descriptors Length",	"mmtp.si.message.mp_table.asset_descriptors.length",	FT_UINT16, BASE_DEC, NULL, 		0x0,   		NULL, HFILL }},
		{ &hf_si_message_table_mp_table_asset_descriptors_bytes,	{ "Asset Descriptors Bytes",	"mmtp.si.message.mp_table.asset_descriptors.bytes",		FT_BYTES,  BASE_NONE, NULL, 	0x0,   		NULL, HFILL }},

		{ &hf_si_message_descriptor_tag,							{ "Descriptor Tag",				"mmtp.si.message.descriptor.tag",						FT_UINT16, BASE_DEC, atsc3_mmtp_signalling_information_descriptor_tags, 		0x0,   		NULL, HFILL }},
		{ &hf_si_message_descriptor_length,							{ "Descriptor Length",			"mmtp.si.message.descriptor.length",					FT_UINT8,  BASE_DEC, NULL, 		0x0,   		NULL, HFILL }},

		//mpu_timestamp_descriptor -
		//for i...n/12
		{ &hf_si_message_descriptor_mpu_timestamp_descriptor_mpu_sequence_number,	{ "MPU Sequence Number",	"mmtp.si.mpu_timestamp_descriptor.mpu_sequence_number",		FT_UINT32,  BASE_DEC, NULL, 		0x0,   		NULL, HFILL }},
		{ &hf_si_message_descriptor_mpu_timestamp_descriptor_mpu_presentation_time,	{ "MPU Presentation Time",	"mmtp.si.mpu_timestamp_descriptor.mpu_presentation_time",	FT_UINT64,  BASE_DEC, NULL, 		0x0,   		NULL, HFILL }},





		//mmt_atsc3_message

		//mmtp.si.message_id == 33024

        { &hf_si_mmt_atsc3_message_service_id,			{ "Service ID", 					"mmtp.si.atsc3.service_id",		 				FT_UINT16, 		BASE_DEC, NULL,										0x00,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_content_type,		{ "Message Content Type", 			"mmtp.si.atsc3.message_content_type",			FT_UINT16, 		BASE_DEC, atsc3_mmtp_si_message_mmt_atsc3_message_type_strings, 										0x00,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_content_version,		{ "Message Content Version", 		"mmtp.si.atsc3.message_content_version",		FT_UINT8,  		BASE_DEC, NULL, 										0x00,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_content_compression,	{ "Message Content Compression", 	"mmtp.si.atsc3.message_content_compression",	FT_UINT8,  		BASE_DEC, NULL, 										0x00,   		NULL, HFILL }},

		{ &hf_si_mmt_atsc3_message_URI_length,			{ "Message Content URI Length", 	"mmtp.si.atsc3.message_content_URI_length",		FT_UINT8,  		BASE_DEC, NULL, 										0x00,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_URI_bytes,			{ "Message Content URI Bytes", 		"mmtp.si.atsc3.message_content_URI_bytes",		FT_STRING,  	STR_ASCII, NULL, 										0x00,   		NULL, HFILL }},

		{ &hf_si_mmt_atsc3_message_content_length,		{ "Message Content Length", 		"mmtp.si.atsc3.message_content_length",			FT_UINT32,  	BASE_DEC, NULL, 										0x00,   		NULL, HFILL }},
		{ &hf_si_mmt_atsc3_message_content_bytes,		{ "Message Content Bytes", 			"mmtp.si.atsc3.message_content_bytes",			FT_BYTES,  		BASE_NONE, NULL, 										0x00,   		NULL, HFILL }},
		{ &hf_si_mmt_atsc3_message_content_bytes_str,	{ "Message Content Bytes", 			"mmtp.si.atsc3.message_content_bytes",			FT_STRING,  	STR_ASCII, NULL, 										0x00,   		NULL, HFILL }},

	    { &hf_si_mmt_atsc3_message_content_descriptor_tag,				{ "Descriptor Tag", 	"mmtp.si.atsc3.message_content.descriptor_tag",			FT_UINT16, 		BASE_DEC, NULL,										0x00,   		NULL, HFILL }},
	    { &hf_si_mmt_atsc3_message_content_descriptor_length,			{ "Descriptor Length",	"mmtp.si.atsc3.message_content.descriptor_length",		FT_UINT16, 		BASE_DEC, NULL, 										0x00,   		NULL, HFILL }},
	    { &hf_si_mmt_atsc3_message_content_descriptor_number_of_assets,	{ "Number of Assets", 	"mmtp.si.atsc3.message_content.number_of_assets",		FT_UINT8,  		BASE_DEC, NULL, 							0x00,   		NULL, HFILL }},

	    { &hf_si_mmt_atsc3_message_content_descriptor_asset_id_length,	{ "Asset ID length", 	"mmtp.si.atsc3.message_content.asset_id_length",		FT_UINT32,  	BASE_DEC, NULL, 							0x0000,   		NULL, HFILL }},
	    { &hf_si_mmt_atsc3_message_content_descriptor_asset_id_bytes,	{ "Asset ID bytes", 	"mmtp.si.atsc3.message_content.asset_id_bytes",			FT_BYTES,  		BASE_NONE, NULL, 							0x00,   		NULL, HFILL }},


		//mmt_atsc3_message VSPD:

		{ &hf_si_mmt_atsc3_message_descriptor_vspd_codec_code,						{ "Codec Code", 										"mmtp.si.atsc3.vspd.codec_code",					FT_STRING,  	STR_ASCII, NULL, 0x00,   		NULL, HFILL }},

        { &hf_si_mmt_atsc3_message_descriptor_vspd_temporal_scalability_present,	{ "Temporal Scalability Present", 						"mmtp.si.atsc3.vspd.temporal_scalability_present",	FT_UINT8,  		BASE_DEC, NULL, 0x80,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_vspd_scalability_info_present,		{ "Scalability Information Present", 					"mmtp.si.atsc3.vspd.scalability_info_present",		FT_UINT8,  		BASE_DEC, NULL, 0x40,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_vspd_multiview_info_present,			{ "Multiview Information Present", 						"mmtp.si.atsc3.vspd.multiview_info_present",		FT_UINT8,  		BASE_DEC, NULL, 0x20,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_vspd_res_cf_bd_info_present,			{ "Resolution/Chroma/Bit Depth Information Present",	"mmtp.si.atsc3.vspd.res_cf_bd_info_present",		FT_UINT8,  		BASE_DEC, NULL, 0x10,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_vspd_pr_info_present,					{ "Picture Rate Information Present", 					"mmtp.si.atsc3.vspd.pr_info_present",				FT_UINT8,  		BASE_DEC, NULL, 0x08,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_vspd_br_info_present,					{ "Bit Rate Information Present", 						"mmtp.si.atsc3.vspd.br_info_present",				FT_UINT8,  		BASE_DEC, NULL, 0x04,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_vspd_color_info_present,				{ "Color Information Present", 							"mmtp.si.atsc3.vspd.color_info_present",			FT_UINT8,  		BASE_DEC, NULL, 0x02,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_vspd_reserved_1,						{ "VSPD reserved_1", 									"mmtp.si.atsc3.vspd.reserved_1",					FT_UINT8,  		BASE_DEC, NULL, 0x01,   		NULL, HFILL }},



		//mmt_atsc3_message CAD:

        { &hf_si_mmt_atsc3_message_descriptor_cad_language_length,	{ "Language Length",	"mmtp.si.atsc3.cad.langauge_length",	FT_UINT8,  		BASE_DEC,	NULL, 0x00,   		NULL, HFILL }},
		{ &hf_si_mmt_atsc3_message_descriptor_cad_language_byte,	{ "Language Bytes", 	"mmtp.si.atsc3.cad.language_bytes",		FT_STRING,  	STR_ASCII,  NULL, 0x00000000,   		NULL, HFILL }},

        { &hf_si_mmt_atsc3_message_descriptor_cad_role,				{ "Role", 				"mmtp.si.atsc3.cad.role",				FT_UINT8,  		BASE_DEC,	NULL, 0xF0,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_cad_aspect_ratio,		{ "Aspect Ratio", 		"mmtp.si.atsc3.cad.aspect_ratio",		FT_UINT8,  		BASE_DEC,	NULL, 0x0F,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_cad_easy_reader,		{ "Easy Reader", 		"mmtp.si.atsc3.cad.easy_reader",		FT_UINT8,  		BASE_DEC,	NULL, 0x80,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_cad_profile,			{ "Profile", 			"mmtp.si.atsc3.cad.profile",			FT_UINT8,  		BASE_DEC,	NULL, 0x60,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_cad_3d_support,		{ "3D Support", 		"mmtp.si.atsc3.cad.3d_support",			FT_UINT8,  		BASE_DEC,	NULL, 0x10,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_cad_reserved_4,		{ "reserved_4 (1111)", 	"mmtp.si.atsc3.cad.reserved_4",			FT_UINT8,  		BASE_DEC,	NULL, 0x0F,   		NULL, HFILL }},


		//mmt_atsc3_message ASPD:
		{ &hf_si_mmt_atsc3_message_descriptor_aspd_codec_code,						{ "Codec Code", 										"mmtp.si.atsc3.aspd.codec_code",					FT_STRING,  	STR_ASCII,  NULL, 0x00000000,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_aspd_num_presentations,				{ "Num Presentations", 									"mmtp.si.atsc3.aspd.num_presentations",				FT_UINT8,  		BASE_DEC,	NULL, 0x00,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_present,		{ "Multi Stream Info Present", 							"mmtp.si.atsc3.aspd.multi_stream_info_present",		FT_UINT8,  		BASE_DEC, 	NULL, 0x80,   		NULL, HFILL }},

		{ &hf_si_mmt_atsc3_message_descriptor_aspd_emergency_info_time_present,		{ "Emergency Info Time Present", 						"mmtp.si.atsc3.aspd.emergency_info_time_present",	FT_UINT8,  		BASE_DEC, 	NULL, 0x40,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_aspd_reserved_6,						{ "Reserved 6 (11 1111)", 								"mmtp.si.atsc3.aspd.reserved_6",					FT_UINT8,  		BASE_DEC, 	NULL, 0x3F,   		NULL, HFILL }},


		//for j < num_presentations
        { &hf_si_mmt_atsc3_message_descriptor_aspd_presentation_id,					{ "Presentation ID", 								"mmtp.si.atsc3.aspd.presentation_id",					FT_UINT8,  		BASE_DEC,	NULL, 0x00,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_aspd_interactivity_enabled,			{ "Interactivity Enabled", 							"mmtp.si.atsc3.aspd.interactivity_enabled",				FT_UINT8,  		BASE_DEC,	NULL, 0x80,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_aspd_profile_channel_config_present,	{ "Profile Channel Config Present", 				"mmtp.si.atsc3.aspd.profile_channel_config_present",	FT_UINT8,  		BASE_DEC,	NULL, 0x40,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_aspd_profile_long,					{ "Profile Long", 									"mmtp.si.atsc3.aspd.profile_long",						FT_UINT8,  		BASE_DEC,	NULL, 0x20,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_aspd_channel_config_long,				{ "Channel Config Long", 							"mmtp.si.atsc3.aspd.channel_config_long",				FT_UINT8,  		BASE_DEC,	NULL, 0x10,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_aspd_audio_renderering_info_present,	{ "Audio Rendering Info Present", 					"mmtp.si.atsc3.aspd.audio_rendering_info_present",		FT_UINT8,  		BASE_DEC,	NULL, 0x08,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_aspd_language_present,				{ "Language Present", 								"mmtp.si.atsc3.aspd.language_present",					FT_UINT8,  		BASE_DEC,	NULL, 0x04,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_aspd_accessibility_role_present,		{ "Accessibility Role Present", 					"mmtp.si.atsc3.aspd.accessibility_role_present",		FT_UINT8,  		BASE_DEC,	NULL, 0x02,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_aspd_label_present,					{ "Label Present", 									"mmtp.si.atsc3.aspd.label_present",						FT_UINT8,  		BASE_DEC,	NULL, 0x01,   		NULL, HFILL }},

		//profile channel config
        { &hf_si_mmt_atsc3_message_descriptor_aspd_profile_level_indiciation_long,		{ "Profile Level_24", 							"mmtp.si.atsc3.aspd.profile_level",						FT_UINT24,  		BASE_DEC,	NULL, 0x000000,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_aspd_profile_level_indiciation,			{ "Profile Level_8", 							"mmtp.si.atsc3.aspd.profile_level",						FT_UINT8, 	 		BASE_DEC,	NULL, 0x00,   		NULL, HFILL }},

		//audio_channel_config
        { &hf_si_mmt_atsc3_message_descriptor_aspd_audio_channel_config_long,		{ "Audio Channel Config_24", 						"mmtp.si.atsc3.aspd.audio_channel_config",						FT_UINT24,  		BASE_DEC,	NULL, 0x000000,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_aspd_audio_channel_config,			{ "Audio Channel Config_8", 						"mmtp.si.atsc3.aspd.audio_channel_config",						FT_UINT8, 	 		BASE_DEC,	NULL, 0x00,   		NULL, HFILL }},


		//audio_renderering_info
        { &hf_si_mmt_atsc3_message_descriptor_aspd_audio_renderering_indiciation,		{ "Audio Renderering Indiciation", 				"mmtp.si.atsc3.aspd.audio_renderering_indiciation",						FT_UINT8, 	 		BASE_DEC,	NULL, 0x00,   		NULL, HFILL }},


		//language_present
        { &hf_si_mmt_atsc3_message_descriptor_aspd_num_languages_minus_1,		{ "Num languages minus 1", 				"mmtp.si.atsc3.aspd.num_languages_minus_1",					FT_UINT8, 	 		BASE_DEC,	NULL, 0x00,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_aspd_language_length,				{ "Language Length", 					"mmtp.si.atsc3.aspd.language_length",						FT_UINT8, 	 		BASE_DEC,	NULL, 0x00,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_aspd_language_bytes,				{ "Language Bytes", 					"mmtp.si.atsc3.aspd.language_bytes",						FT_STRING, 	 		STR_ASCII,	NULL, 0x00,   		NULL, HFILL }},

        { &hf_si_mmt_atsc3_message_descriptor_aspd_accessibility,				{ "Accessibility", 						"mmtp.si.atsc3.aspd.accessibility",							FT_UINT8, 	 		BASE_DEC,	NULL, 0x00,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_aspd_role,						{ "Role", 								"mmtp.si.atsc3.aspd.role",									FT_UINT8, 	 		BASE_DEC,	NULL, 0x00,   		NULL, HFILL }},


		//label
        { &hf_si_mmt_atsc3_message_descriptor_aspd_label_length,				{ "Label Length", 						"mmtp.si.atsc3.aspd.label_length",						FT_UINT8, 	 		BASE_DEC,	NULL, 0x00,   		NULL, HFILL }},
        { &hf_si_mmt_atsc3_message_descriptor_aspd_label_data_bytes,			{ "Label Data Bytes", 					"mmtp.si.atsc3.aspd.label_data_bytes",							FT_BYTES, 	 		BASE_NONE,	NULL, 0x00,   		NULL, HFILL }},

		//multi_stream_info_present


		//presentation_aux_stream_info

	   { &hf_si_mmt_atsc3_message_descriptor_aspd_presentation_aux_stream_num_presentation_aux_streams,		{ "Num Presentations Aux Streams", 	"mmtp.si.atsc3.aspd.presentation_aux_stream.num_presentation_aux_stream",			FT_UINT8, 	 		BASE_DEC,	NULL, 0x00,   		NULL, HFILL }},
	   { &hf_si_mmt_atsc3_message_descriptor_aspd_presentation_aux_stream_id,								{ "Aux Stream ID", 					"mmtp.si.atsc3.aspd.presentation_aux_stream.id",									FT_UINT8, 	 		BASE_DEC,	NULL, 0x00,   		NULL, HFILL }},




		//multi_stream_info

	   { &hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_this_is_main_stream,		{ "This is Main Stream", 		"mmtp.si.atsc3.aspd.multi_stream_info.this_is_main_stream",		FT_UINT8, 	 		BASE_DEC,	NULL, 0x80,   		NULL, HFILL }},
	   { &hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_this_stream_id,				{ "This Stream ID", 			"mmtp.si.atsc3.aspd.multi_stream_info.this_stream_id",			FT_UINT8, 	 		BASE_DEC,	NULL, 0x7F,   		NULL, HFILL }},

	   { &hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_reserved_1,					{ "reserved_1 (1)", 			"mmtp.si.atsc3.aspd.multi_stream_info.reserved_1",				FT_UINT8, 	 		BASE_DEC,	NULL, 0x80,   		NULL, HFILL }},
	   { &hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_bundle_id,					{ "Bundle ID", 					"mmtp.si.atsc3.aspd.multi_stream_info.bundle_id",				FT_UINT8, 	 		BASE_DEC,	NULL, 0x7F,   		NULL, HFILL }},

	   { &hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_reserved_1_main_stream,		{ "reserved_1_main_stream (1)", "mmtp.si.atsc3.aspd.multi_stream_info.reserved_1_main_stream",	FT_UINT8, 	 		BASE_DEC,	NULL, 0x80,   		NULL, HFILL }},
	   { &hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_num_auxiliary_streams,		{ "Num Auxiliary Streams", 		"mmtp.si.atsc3.aspd.multi_stream_info.num_auxiliary_streams",	FT_UINT8, 	 		BASE_DEC,	NULL, 0x7F,   		NULL, HFILL }},

	   //for m < num_auxiliary_streams

	   { &hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_delivery_method,			{ "Delivery Method", 			"mmtp.si.atsc3.aspd.multi_stream_info.delivery_method",			FT_UINT8, 	 		BASE_DEC,	NULL, 0x80,   		NULL, HFILL }},
	   { &hf_si_mmt_atsc3_message_descriptor_aspd_multi_stream_info_auxiliary_stream_id,		{ "Auxiliary Stream ID", 		"mmtp.si.atsc3.aspd.multi_stream_info.auxiliary_stream_id",		FT_UINT8, 	 		BASE_DEC,	NULL, 0x7F,   		NULL, HFILL }},


		//emergency_time_info
	   { &hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_start_time_present,		{ "Emergency Information Start Time Present",	"mmtp.si.atsc3.aspd.emergency_information_time_info.start_time_present",	FT_UINT8, 	BASE_DEC,	NULL, 0x80,   		NULL, HFILL }},
	   { &hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_end_time_present,		{ "Emergency Information End Time Present", 	"mmtp.si.atsc3.aspd.emergency_information_time_info.end_time_present",		FT_UINT8, 	BASE_DEC,	NULL, 0x40,   		NULL, HFILL }},
	   { &hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_reserved_6,				{ "reserved_6", 								"mmtp.si.atsc3.aspd.emergency_information_time_info.reserved_6",			FT_UINT8, 	 BASE_DEC,	NULL, 0x3F,   		NULL, HFILL }},


	   //if hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_start_time_present
	   { &hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_start_time,				{ "Emergency Information Start Time (S)",	"mmtp.si.atsc3.aspd.emergency_information_time_info.start_time_s",			FT_UINT32, 	BASE_DEC,	NULL, 0x00000000,  		NULL, HFILL }},
	   { &hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_start_time_reserved_6,	{ "reserved_6 (11 11111)", 					"mmtp.si.atsc3.aspd.emergency_information_time_info.start_time_reserved_6",	FT_UINT16, 	BASE_DEC,	NULL, 0xFC00,   		NULL, HFILL }},
	   { &hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_start_time_ms,			{ "Emergency Information Start Time (MS)",	"mmtp.si.atsc3.aspd.emergency_information_time_info.start_time_ms",			FT_UINT16, 	BASE_DEC,	NULL, 0x03FF,   		NULL, HFILL }},

	   //if
	   { &hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_end_time,				{ "Emergency Information End Time (S)",		"mmtp.si.atsc3.aspd.emergency_information_time_info.end_time_s",			FT_UINT32, 	BASE_DEC,	NULL, 0x00000000,  		NULL, HFILL }},
	   { &hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_end_time_reserved_6,	{ "reserved_6 (11 11111)", 					"mmtp.si.atsc3.aspd.emergency_information_time_info.end_time_reserved_6",	FT_UINT16, 	BASE_DEC,	NULL, 0xFC00,   		NULL, HFILL }},
	   { &hf_si_mmt_atsc3_message_descriptor_aspd_emergency_information_end_time_ms,			{ "Emergency Information End Time (MS)",	"mmtp.si.atsc3.aspd.emergency_information_time_info.end_time_ms",			FT_UINT16, 	BASE_DEC,	NULL, 0x03FF,   		NULL, HFILL }},



	   //hrbm_message

       { &hf_si_hrbm_message_max_buffer_size,		 				{ "Max Buffer Size", 			"mmtp.si.hrbm.max_buffer_size",		 		FT_UINT32, BASE_DEC, NULL,	0x00,   		NULL, HFILL }},
       { &hf_si_hrbm_message_fixed_end_to_end_delay,		 		{ "Fixed end-to-end delay", 	"mmtp.si.hrbm.fixed_end_to_end_delay",		FT_UINT32, BASE_DEC, NULL, 	0x00,   		NULL, HFILL }},
	   { &hf_si_hrbm_message_max_transmission_delay,		 		{ "Max transmission delay", 	"mmtp.si.hrbm.max_transmission_delay",		FT_UINT32, BASE_DEC, NULL, 	0x00,   		NULL, HFILL }},


	   //hrbm_removal_message
       { &hf_si_hrbm_removal_message_number_of_operation_modes,		{ "Number of operation modes", 		"mmtp.si.hrbm_removal.number_of_operation_modes",		FT_UINT8, BASE_DEC, NULL,	0x00,   		NULL, HFILL }},
       { &hf_si_hrbm_removal_message_data_removal_type,		 		{ "Data Removal Type", 				"mmtp.si.hrbm_removal.data_removal_type",				FT_UINT8, BASE_DEC, NULL, 	0x00,   		NULL, HFILL }},
       { &hf_si_hrbm_removal_message_max_decapsulation_buffer_size,	{ "Max Decapsulation Buffer Size", 	"mmtp.si.hrbm_removal.max_decapsulation_buffer_size",	FT_UINT32, BASE_DEC, NULL, 	0x00,   		NULL, HFILL }},
       { &hf_si_hrbm_removal_message_buffer_management_valid,		{ "Buffer Management Valid", 		"mmtp.si.hrbm_removal.buffer_management_valid",			FT_UINT8, BASE_DEC, NULL, 	0x80,   		NULL, HFILL }},
       { &hf_si_hrbm_removal_message_reserved_7,		 			{ "reserved_7", 					"mmtp.si.hrbm_removal.reserved_7",						FT_UINT8, BASE_DEC, NULL, 	0x7F,   		NULL, HFILL }},



		//atsc3_mmtp_si_message_mmt_atsc3_message_type_strings

		///
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

		&ett_mmtp_signalling_message_pa_message,

		&ett_mmtp_signalling_message_mpi_message_subset,
		&ett_mmtp_signalling_message_mpi_message_complete,

		&ett_mmtp_signalling_message_mpt_message_subset,
		&ett_mmtp_signalling_message_mpt_message_complete,

		&ett_mmtp_signalling_message_cri_message,
		&ett_mmtp_signalling_message_dci_message,
		&ett_mmtp_signalling_message_sswr_message,
		&ett_mmtp_signalling_message_al_fec_message,
		&ett_mmtp_signalling_message_hrbm_message,
		&ett_mmtp_signalling_message_mc_message,
		&ett_mmtp_signalling_message_ac_message,
		&ett_mmtp_signalling_message_af_message,
		&ett_mmtp_signalling_message_rqf_message,
		&ett_mmtp_signalling_message_adc_message,
		&ett_mmtp_signalling_message_hrbm_removal_message,
		&ett_mmtp_signalling_message_ls_message,
		&ett_mmtp_signalling_message_lr_message,
		&ett_mmtp_signalling_message_namf_message,
		&ett_mmtp_signalling_message_ldc_message,

		//a331-2022 extensions
		&ett_mmtp_signalling_message_mmt_atsc3_message_vspd,
		&ett_mmtp_signalling_message_mmt_atsc3_message_cad,
		&ett_mmtp_signalling_message_mmt_atsc3_message_aspd,

		&ett_mmtp_repair_symbol
    };

    static ei_register_info ei[] = {
        { &ei_version1_only, 									{ "mmt.version1_only", PI_PROTOCOL, PI_WARN, "Sorry, this dissector supports MMTP version 1 only", EXPFILL }},
        { &ei_payload_decompress_failed, 						{ "mmt.si.atsc3.unable_to_decompress", PI_PROTOCOL, PI_WARN, "Unable to decompress mmt_atsc3_message payload", EXPFILL }},

		//hack-ish
        { &ei_atsc3_mmt_atsc3_message_content_type_unknown, 	{ "mmt.si.atsc3.message_content_type_unknown", PI_PROTOCOL, PI_WARN, "mmt_atsc3_message: message_content_type unknown", EXPFILL }},


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
