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

static const value_string atsc3_mmtp_mpu_fragment_type_isobmff_box_name [] = {
	{ 0x0, 		"moov" },
	{ 0x1, 		"mdat" },
	{ 0x2, 		"moof" },
	{ 0x3, 		"mhas" },
	{ 0,       	NULL }
};

/* MMT - mpu_fragment type  */
static const value_string atsc3_mmtp_fragmentation_indiciator [] = {
	{ 0x0, 		"Complete DU" },
	{ 0x1, 		"First DU Fragment" },
	{ 0x2, 		"Middle DU Fragment" },
	{ 0x3, 		"Last DU Fragment" },
	{ 0,       	NULL }
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


/* Common RMT exported functions */
/* ============================= */
extern int atsc3_lct_ext_decode(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint offset, guint offset_max, lct_data_exchange_t *data_exchange,
                   int hfext, int ettext);
extern void atsc3_fec_decode_ext_fti(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint8 encoding_id);

extern double atsc3_route_decode_send_rate(guint16 send_rate );

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
