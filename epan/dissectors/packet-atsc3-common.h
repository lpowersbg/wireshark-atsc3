/* packet-atsc3-common.h
 * ATSC 3.0
 * Common function definitions
 * Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_RMT_COMMON__
#define __PACKET_RMT_COMMON__

#include <epan/params.h>
#include <glib.h>
#include <epan/conversation.h>


#include <stdlib.h>
#include "reassemble.h"
#include "packet-xml.h"
#include "proto_data.h"

//jjustman-2022-09-13 - for htonl
#ifdef HAVE_ARPA_INET_H
    #include <arpa/inet.h>
#endif

#ifdef _WIN32
	#include <winsock2.h>
	#include <malloc.h>
#endif

/* ATSC3.0 LLS Info */
#define ATSC3_LLS_IP_ADDRESS 		224.0.23.60
#define ATSC3_LLS_IP_ADDRESS_UINT 	3758102332
#define ATSC3_LLS_UDP_PORT			4937


/* from libatsc3 - atsc3_lls_types.h
 *
 *
	typedef enum {
		SLT = 0x01,
		RRT = 0x02,
		SystemTime = 0x03,
		AEAT = 0x04,
		OnscreenMessageNotification = 0x05,
		CertificationData = 0x06,
		SignedMultiTable = 0xFE,
		UserDefined = 0xFF,
		RESERVED = 0x00,             //anything else...
	} lls_table_type_t;
 */

static const value_string atsc3_lls_table_strings[] = {
	{ 0x01, 	"SLT" },
	{ 0x02, 	"RRT" },
	{ 0x03, 	"SystemTime" },
	{ 0x04, 	"AEAT" },
	{ 0x05, 	"OnscreenMessageNotification" },
	{ 0x06, 	"CertificationData" },
	{ 0xFE, 	"SignedMultiTable" },
	{ 0xFF, 	"UserDefined" },
	{ 0,       	NULL }
};


/* MMT - payload_type */
static const value_string atsc3_mmtp_payload_type [] = {
	{ 0x0, 		"MPU" },
	{ 0x1, 		"Generic Object" },
	{ 0x2, 		"Signalling Message" },
	{ 0x3, 		"Repair Symbol" },
	{ 0,       	NULL }
};


/* MMT - mpu_fragment type  */
static const value_string atsc3_mmtp_mpu_fragment_type [] = {
	{ 0x0, 		"Init/MPU Metadata" },
	{ 0x1, 		"Movie Fragment Metadata" },
	{ 0x2, 		"MFU" },
	{ 0x3, 		"Hint" },
	{ 0,       	NULL }
};

#define ATSC3_MMT_MPU_FRAGMENT_TYPE_MOOV 0x0
#define ATSC3_MMT_MPU_FRAGMENT_TYPE_MOOF 0x1
#define ATSC3_MMT_MPU_FRAGMENT_TYPE_MDAT 0x2
#define ATSC3_MMT_MPU_FRAGMENT_TYPE_MHAS 0x3


static const value_string atsc3_mmtp_mpu_fragment_type_isobmff_box_name [] = {
	{ ATSC3_MMT_MPU_FRAGMENT_TYPE_MOOV, 		"moov" },
	{ ATSC3_MMT_MPU_FRAGMENT_TYPE_MOOF, 		"moof" },
	{ ATSC3_MMT_MPU_FRAGMENT_TYPE_MDAT, 		"mdat" },
	{ ATSC3_MMT_MPU_FRAGMENT_TYPE_MHAS, 		"mhas" },
	{ 0,       	NULL }
};

/* MMT - mpu_fragment type  */
static const value_string atsc3_mmtp_mpu_fragmentation_indiciator [] = {
	{ 0x0, 		"Complete DU" },
	{ 0x1, 		"First DU Fragment" },
	{ 0x2, 		"Middle DU Fragment" },
	{ 0x3, 		"Last DU Fragment" },
	{ 0,       	NULL }
};


/* MMT - mpu_fragment type  */
static const value_string atsc3_mmtp_si_fragmentation_indiciator [] = {
	{ 0x0, 		"Complete Signalling Message" },
	{ 0x1, 		"First SI Message Fragment" },
	{ 0x2, 		"Middle SI Message Fragment" },
	{ 0x3, 		"Last SI Message Fragment" },
	{ 0,       	NULL }
};

//borrowed from libatsc3


#define PA_message 				        0x0000

#define MPI_message				        0x0001
#define MPI_message_start 		        0x0001
#define MPI_message_end	 		        0x0010

#define MPT_message				        0x0011
#define MPT_message_start		        0x0011
#define MPT_message_end			        0x0020
//		RESERVED				        0x0021 ~ 0x01FF

#define	CRI_message				        0x0200
#define	DCI_message				        0x0201
#define	SSWR_message			        0x0202
#define	AL_FEC_message			        0x0203
#define	HRBM_message			        0x0204
#define	MC_message				        0x0205
#define	AC_message				        0x0206
#define	AF_message				        0x0207
#define	RQF_message				        0x0208
#define	ADC_message				        0x0209
#define	HRB_removal_message		        0x020A
#define	LS_message				        0x020B
#define	LR_message				        0x020C
#define	NAMF_message			        0x020D
#define	LDC_message				        0x020E
//Reserved for private use 		        0x8000 ~ 0xFFFF

#define	MMT_ATSC3_MESSAGE_ID		    0x8100
#define	SIGNED_MMT_ATSC3_MESSAGE_ID	    0x8101

//From A/331:2020 - Table 7.8 Code Values for atsc3_message_content_type

#define MMT_ATSC3_MESSAGE_CONTENT_TYPE_RESERVED			                    0x0000

#define MMT_ATSC3_MESSAGE_CONTENT_TYPE_UserServiceDescription               0x0001

//redundant, but...as needed...
#define MMT_ATSC3_MESSAGE_CONTENT_TYPE_MPD_FROM_DASHIF                      0x0002

//HELD trigger is in the MMT SLS (SI message), not as part of the fdt-instance as in ROUTE
#define MMT_ATSC3_MESSAGE_CONTENT_TYPE_HELD                                 0x0003

//see atsc3_mmt_signalling_message.c: mmt_atsc3_message_payload_parse
// NOTE: this should be a first class citizen from the signaller direct api invocation for creating this emission,
// and will be wrapped as an  with relevant ntp_timestamp, see MMT design proposal for this use case in libatsc3
#define MMT_ATSC3_MESSAGE_CONTENT_TYPE_APPLICATION_EVENT_INFORMATION_A337   0x0004

#define MMT_ATSC3_MESSAGE_CONTENT_TYPE_VIDEO_STREAM_PROPERTIES_DESCRIPTOR   0x0005
#define MMT_ATSC3_MESSAGE_CONTENT_TYPE_ATSC_STAGGERCAST_DESCRIPTOR          0x0006

//re-wrapping of upstream emsg box "translated" into an inband_event_descriptor, see A/337:2019 table 4.3 for more details
//remember the emsg box is present in the movie fragment metadata (e.g. mpu_fragment_type = 0x01), so if you are using OOO MMT, this will most likely be delivered "late",
// as the MOOF atom will come at the close of the mpu sequence/GOP, so use 0x0004 instead as a real-time SI message creation in the signaller
#define MMT_ATSC3_MESSAGE_CONTENT_TYPE_INBAND_EVENT_DESCRIPTOR_A337         0x0007

#define MMT_ATSC3_MESSAGE_CONTENT_TYPE_CAPTION_ASSET_DESCRIPTOR             0x0008
#define MMT_ATSC3_MESSAGE_CONTENT_TYPE_AUDIO_STREAM_PROPERTIES_DESCRIPTOR   0x0009
#define MMT_ATSC3_MESSAGE_CONTENT_TYPE_DWD                                  0x000A
#define MMT_ATSC3_MESSAGE_CONTENT_TYPE_RSAT_A200                            0x000B

#define MMT_ATSC3_MESSAGE_CONTENT_TYPE_SECURITY_PROPERTIES_DESCRIPTOR       0x000C

//jjustman-2021-06-03: TODO - implement additional SI for LA_url support
#define MMT_ATSC3_MESSAGE_CONTENT_TYPE_SECURITY_PROPERTIES_DESCRIPTOR_LAURL	0x000D

//reserved to 0x000E ~ 0xFFFF
#define MMT_ATSC3_MESSAGE_CONTENT_TYPE_RESERVED_FUTURE                      0x000E


#define MMT_SCTE35_Signal_Message		0xF337	// SCTE35_Signal_Message Type
#define MMT_SCTE35_Signal_Descriptor	0xF33F	// SCTE35_Signal_Descriptor tag


static const value_string atsc3_mmtp_si_message_type_strings [] = {
	{ 0x0000, 		"PA_message" },

	{ 0x0001, 		"MPI_message 1" },
	{ 0x0002, 		"MPI_message 2" },
	{ 0x0003, 		"MPI_message 3" },
	{ 0x0004, 		"MPI_message 4" },
	{ 0x0005, 		"MPI_message 5" },
	{ 0x0006, 		"MPI_message 6" },
	{ 0x0007, 		"MPI_message 7" },
	{ 0x0008, 		"MPI_message 8" },
	{ 0x0009, 		"MPI_message 9" },
	{ 0x000A, 		"MPI_message 10" },
	{ 0x000B, 		"MPI_message 11" },
	{ 0x000C, 		"MPI_message 12" },
	{ 0x000D, 		"MPI_message 13" },
	{ 0x000E, 		"MPI_message 14" },
	{ 0x000F, 		"MPI_message 15" },
	{ 0x0010, 		"MPI_message 16" },

	{ 0x0011, 		"MPT_message 1" },
	{ 0x0012, 		"MPT_message 2" },
	{ 0x0013, 		"MPT_message 3" },
	{ 0x0014, 		"MPT_message 4" },
	{ 0x0015, 		"MPT_message 5" },
	{ 0x0016, 		"MPT_message 6" },
	{ 0x0017, 		"MPT_message 7" },
	{ 0x0018, 		"MPT_message 8" },
	{ 0x0019, 		"MPT_message 9" },
	{ 0x001A, 		"MPT_message 10" },
	{ 0x001B, 		"MPT_message 11" },
	{ 0x001C, 		"MPT_message 12" },
	{ 0x001D, 		"MPT_message 13" },
	{ 0x001E, 		"MPT_message 14" },
	{ 0x001F, 		"MPT_message 15" },
	{ 0x0020, 		"MPT_message 16" },


	//todo - do the rest of the messages

	{ HRBM_message, 		"HRBM_message" },
	{ HRB_removal_message, 	"HRB_removal_message" },

	//...
	{ MMT_ATSC3_MESSAGE_ID, 		"MMT_ATSC3_MESSAGE" },
	{ SIGNED_MMT_ATSC3_MESSAGE_ID, 	"SIGNED_MMT_ATSC3_MESSAGE_ID" },
	{ 0,       	NULL }

};

static const value_string atsc3_mmtp_si_message_mmt_atsc3_message_type_strings [] = {
	{ MMT_ATSC3_MESSAGE_CONTENT_TYPE_RESERVED, 								"RESERVED" },
	{ MMT_ATSC3_MESSAGE_CONTENT_TYPE_UserServiceDescription, 				"USBD" },
	{ MMT_ATSC3_MESSAGE_CONTENT_TYPE_MPD_FROM_DASHIF, 						"MPD_FROM_DASHIF" },
	{ MMT_ATSC3_MESSAGE_CONTENT_TYPE_HELD, 									"HELD" },
	{ MMT_ATSC3_MESSAGE_CONTENT_TYPE_APPLICATION_EVENT_INFORMATION_A337, 	"AEI_A337" },
	{ MMT_ATSC3_MESSAGE_CONTENT_TYPE_INBAND_EVENT_DESCRIPTOR_A337, 			"INBAND_A337" },

	//UGH
	{ MMT_ATSC3_MESSAGE_CONTENT_TYPE_ATSC_STAGGERCAST_DESCRIPTOR,			"STAGGERCAST_DESC" },

	//*SPD's
	{ MMT_ATSC3_MESSAGE_CONTENT_TYPE_VIDEO_STREAM_PROPERTIES_DESCRIPTOR,	"VSPD" },

	{ MMT_ATSC3_MESSAGE_CONTENT_TYPE_CAPTION_ASSET_DESCRIPTOR, 				"CAD" },
	{ MMT_ATSC3_MESSAGE_CONTENT_TYPE_AUDIO_STREAM_PROPERTIES_DESCRIPTOR, 	"ASPD" },
	{ MMT_ATSC3_MESSAGE_CONTENT_TYPE_DWD, 									"DWD" },

	{ MMT_ATSC3_MESSAGE_CONTENT_TYPE_RSAT_A200, 							"RSAT_A200" },

	{ MMT_ATSC3_MESSAGE_CONTENT_TYPE_SECURITY_PROPERTIES_DESCRIPTOR, 		"SEC_PD" },
	{ MMT_ATSC3_MESSAGE_CONTENT_TYPE_SECURITY_PROPERTIES_DESCRIPTOR_LAURL, 	"SEC_PD_LAURL" },
	{ MMT_ATSC3_MESSAGE_CONTENT_TYPE_RESERVED_FUTURE, 						"RESERVED" },


	{ 0,       	NULL }


};


#define MMT_CRI_DESCRIPTOR 				0x0000
#define MMT_MPU_TIMESTAMP_DESCRIPTOR 	0x0001
#define MMT_DEPENDENCY_DESCRIPTOR 		0x0002
#define MMT_GFDT_DESCRIPTOR 			0x0003
#define MMT_SI_DESCRIPTOR				0x0004

static const value_string atsc3_mmtp_signalling_information_descriptor_tags [] = {
		{ MMT_CRI_DESCRIPTOR, 				"MMT_CRI_DESCRIPTOR" },
		{ MMT_MPU_TIMESTAMP_DESCRIPTOR,		"MMT_MPU_TIMESTAMP_DESCRIPTOR" },
		{ MMT_DEPENDENCY_DESCRIPTOR,		"MMT_DEPENDENCY_DESCRIPTOR" },
		{ MMT_GFDT_DESCRIPTOR, 				"MMT_GFDT_DESCRIPTOR" },
		{ MMT_SI_DESCRIPTOR, 				"MMT_SI_DESCRIPTOR" },
		{ 0,       							NULL }

};

#define MMT_IDENTIFIER_TYPE_MAPPING_ASSET_ID				0x00
#define MMT_IDENTIFIER_TYPE_MAPPING_URL			 			0x01
#define MMT_IDENTIFIER_TYPE_MAPPING_REGEX		 			0x02
#define MMT_IDENTIFIER_TYPE_MAPPING_DASH_REPRESENTATION_ID 	0x03
#define MMT_IDENTIFIER_TYPE_MAPPING_PRIVATE				 	0x04


static const value_string atsc3_mmtp_signalling_information_identifier_type_mapping [] = {
		{ MMT_IDENTIFIER_TYPE_MAPPING_ASSET_ID, 				"MMT_IDENTIFIER_TYPE_MAPPING_ASSET_ID" },
		{ MMT_IDENTIFIER_TYPE_MAPPING_URL,						"MMT_IDENTIFIER_TYPE_MAPPING_URL" },
		{ MMT_IDENTIFIER_TYPE_MAPPING_REGEX,					"MMT_IDENTIFIER_TYPE_MAPPING_REGEX" },
		{ MMT_IDENTIFIER_TYPE_MAPPING_DASH_REPRESENTATION_ID,	"MMT_IDENTIFIER_TYPE_MAPPING_DASH_REPRESENTATION_ID" },
		{ MMT_IDENTIFIER_TYPE_MAPPING_PRIVATE, 					"MMT_IDENTIFIER_TYPE_MAPPING_PRIVATE" },
		{ 0,       												NULL }

};

#define MMT_LOCATION_TYPE_SAME_MMTP_PACKET_FLOW 				0x00
#define MMT_LOCATION_TYPE_MMTP_FLOW_UDP_IP_V4 					0x01
#define MMT_LOCATION_TYPE_MMTP_FLOW_UDP_IP_V6					0x02
#define MMT_LOCATION_TYPE_ES_IN_MPEG2TS_BROADCAST 				0x03
#define MMT_LOCATION_TYPE_ES_IN_MPEG2TS_IP_BROADCAST			0x04
#define MMT_LOCATION_TYPE_URL									0x05
#define MMT_LOCATION_TYPE_RESERVED_PRIVATE_LOCATION_INFORMATION	0x06
#define MMT_LOCATION_TYPE_SAME_SI_GLI							0x07
#define MMT_LOCATION_TYPE_SAME_SI_DATA_PATH_GLI					0x08
#define MMT_LOCATION_TYPE_SAME_IP_UDP_V4_GLI					0x09
#define MMT_LOCATION_TYPE_SAME_IP_UDP_V4_DATA_PATH			 	0x0A
#define MMT_LOCATION_TYPE_SAME_IP_UDP_V6_DATA_PATH 				0x0B
#define MMT_LOCATION_TYPE_ES_IN_MPEG2TS_IPV4_BROADCAST			0x0C
#define MMT_LOCATION_TYPE_RESERVED 								0x0D


static const value_string atsc3_mmtp_signalling_information_location_type_mapping [] = {
		{ MMT_LOCATION_TYPE_SAME_MMTP_PACKET_FLOW, 					"MMT_LOCATION_TYPE_SAME_MMTP_PACKET_FLOW" },
		{ MMT_LOCATION_TYPE_MMTP_FLOW_UDP_IP_V4,					"MMT_LOCATION_TYPE_MMTP_FLOW_UDP_IP_V4" },
		{ MMT_LOCATION_TYPE_MMTP_FLOW_UDP_IP_V6,					"MMT_LOCATION_TYPE_MMTP_FLOW_UDP_IP_V6" },
		{ MMT_LOCATION_TYPE_ES_IN_MPEG2TS_BROADCAST,				"MMT_LOCATION_TYPE_ES_IN_MPEG2TS_BROADCAST" },
		{ MMT_LOCATION_TYPE_ES_IN_MPEG2TS_IP_BROADCAST, 			"MMT_LOCATION_TYPE_ES_IN_MPEG2TS_IP_BROADCAST" },
		{ MMT_LOCATION_TYPE_URL, 									"MMT_LOCATION_TYPE_URL" },
		{ MMT_LOCATION_TYPE_RESERVED_PRIVATE_LOCATION_INFORMATION, 	"MMT_LOCATION_TYPE_RESERVED_PRIVATE_LOCATION_INFORMATION" },
		{ MMT_LOCATION_TYPE_SAME_SI_GLI, 							"MMT_LOCATION_TYPE_SAME_SI_GLI" },
		{ MMT_LOCATION_TYPE_SAME_SI_DATA_PATH_GLI, 					"MMT_LOCATION_TYPE_SAME_SI_DATA_PATH_GLI" },
		{ MMT_LOCATION_TYPE_SAME_IP_UDP_V4_GLI, 					"MMT_LOCATION_TYPE_SAME_IP_UDP_V4_GLI" },
		{ MMT_LOCATION_TYPE_SAME_IP_UDP_V4_DATA_PATH, 				"MMT_LOCATION_TYPE_SAME_IP_UDP_V4_DATA_PATH" },
		{ MMT_LOCATION_TYPE_SAME_IP_UDP_V6_DATA_PATH, 				"MMT_LOCATION_TYPE_SAME_IP_UDP_V6_DATA_PATH" },
		{ MMT_LOCATION_TYPE_ES_IN_MPEG2TS_IPV4_BROADCAST, 			"MMT_LOCATION_TYPE_ES_IN_MPEG2TS_IPV4_BROADCAST" },
		{ MMT_LOCATION_TYPE_RESERVED, 								"MMT_LOCATION_TYPE_RESERVED" },
		{ 0,       													NULL }
};


/* STLTP defines
 *
 From A/324:2022-06

 81 ('1010001') DSTP Data Source Transport Protocol Tunnel Packets and
Information Headers
82 ('1010010') ALPTP ALP Transport Protocol Tunnel Packets and
Information Headers
97 ('1100001') STLTP STL Transport Protocol Tunnel Packets
*/

#define ATSC3_STLTP_CTP_OUTER_PAYLOAD_TYPE_DSTP 	0x51
#define ATSC3_STLTP_CTP_OUTER_PAYLOAD_TYPE_ALPTP 	0x52
#define ATSC3_STLTP_CTP_OUTER_PAYLOAD_TYPE_STLTP 	0x61


static const value_string atsc3_stltp_ctp_outer_payload_type_mapping [] = {
		{ ATSC3_STLTP_CTP_OUTER_PAYLOAD_TYPE_DSTP, 				"DSTP" },
		{ ATSC3_STLTP_CTP_OUTER_PAYLOAD_TYPE_ALPTP,				"ALPTP" },
		{ ATSC3_STLTP_CTP_OUTER_PAYLOAD_TYPE_STLTP,				"STLTP" },
		{ 0,       												NULL }
};


#define ATSC3_STLTP_CTP_INNER_PAYLOAD_TYPE_TIMING_AND_MANAGEMENT 								0x4C
#define ATSC3_STLTP_CTP_INNER_PAYLOAD_TYPE_PREAMBLE											 	0x4D
#define ATSC3_STLTP_CTP_INNER_PAYLOAD_TYPE_BASEBAND_PACKET										0x4E
#define ATSC3_STLTP_CTP_INNER_PAYLOAD_TYPE_SECURITY_DATA_STREAM_AUTHENTICATION_KEY 				0x4F
/* jjustman-2022-09-13 - todo - cross check these */
#define ATSC3_STLTP_CTP_INNER_PAYLOAD_TYPE_SECURITY_DATA_STREAM									0x50
#define ATSC3_STLTP_CTP_INNER_PAYLOAD_TYPE_SECURITY_DATA_STREAM_SIGNING_ENTITY_PUBLIC_KEYS		0x51


static const value_string atsc3_stltp_ctp_inner_payload_type_mapping [] = {
		{ ATSC3_STLTP_CTP_INNER_PAYLOAD_TYPE_TIMING_AND_MANAGEMENT, 							"T&M" },
		{ ATSC3_STLTP_CTP_INNER_PAYLOAD_TYPE_PREAMBLE,											"Preamble" },
		{ ATSC3_STLTP_CTP_INNER_PAYLOAD_TYPE_BASEBAND_PACKET,									"BBP" },
		{ ATSC3_STLTP_CTP_INNER_PAYLOAD_TYPE_SECURITY_DATA_STREAM_AUTHENTICATION_KEY, 			"SDS-AUTHKEY" },
		{ ATSC3_STLTP_CTP_INNER_PAYLOAD_TYPE_SECURITY_DATA_STREAM, 								"SDS" },
		{ ATSC3_STLTP_CTP_INNER_PAYLOAD_TYPE_SECURITY_DATA_STREAM_SIGNING_ENTITY_PUBLIC_KEYS, 	"SDS-PUBLICKEYS" },
		{ 0,       												NULL }
};



/* LCT preferences */

#define LCT_PREFS_EXT_192_NONE 0
#define LCT_PREFS_EXT_192_FLUTE 1

#define LCT_PREFS_EXT_193_NONE 0
#define LCT_PREFS_EXT_193_FLUTE 1


extern const enum_val_t enum_lct_ext_192[];
extern const enum_val_t enum_lct_ext_193[];

/* String tables external references */
extern const value_string string_fec_encoding_id[];


/* Structures to exchange data between RMT dissectors */
/* ============================= */
typedef struct lct_data_exchange
{

	//jjustman-2022-09-06 - should be quint32 to be in alignment with a/331
	guint64 tsi;
	guint64 toi;

	/* inputs */
//	qint ext_48; //EXT_TOL_48
//	qint ext_66; //EXT_ROUTE_PRESENTATION_TIME
	gint ext_192;
	gint ext_193;
//	qint ext_194; //EXT_TOL_24


	/* outputs */
	guint8 codepoint;
	gboolean is_flute;

} lct_data_exchange_t;

typedef struct fec_data_exchange
{
	/* inputs */
	guint8 encoding_id;

} fec_data_exchange_t;



/* Common ATSC3 exported functions */
/* ============================= */

#define DPRINT(arg) \
          g_printerr("%*.*s%s: ", \
                     1,1," ", \
                     G_STRLOC); \
          g_printerr arg; \
          g_printerr("\n")



extern void atsc_lls_slt_add_conversations_from_xml_dissector(xml_frame_t* xml_dissector_frame);
extern void atsc3_mmt_atsc3_message_usbd_parse_routecomponent(xml_frame_t* xml_dissector_frame);

extern int atsc3_lct_ext_decode(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint offset, guint offset_max, lct_data_exchange_t *data_exchange,
                   int hfext, int ettext);
extern void atsc3_fec_decode_ext_fti(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint8 encoding_id);

extern double atsc3_route_decode_send_rate(guint16 send_rate );

extern guint atsc3_mmt_atsc3_message_decode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 si_message_mmt_atsc3_message_service_id, guint32 si_message_mmt_atsc3_message_content_type);

extern guint atsc3_mmt_atsc3_message_descriptor_header_decode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

extern guint atsc3_mmtp_mp_table_decode(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree);

extern guint atsc3_mmt_descriptor_decode(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree);
//
//extern xml_frame_t *__internal_xml_get_tag(xml_frame_t *frame, const gchar *name);
//extern xml_frame_t *__internal_xml_get_first_child_tag(xml_frame_t *frame, const gchar *name);

// proto dissector registration


extern int proto_atsc3_route;
extern int proto_atsc3_mmtp;


#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
