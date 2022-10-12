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


//jjustman-2022-10-08 - hack


char* ATSC3_A360_CERTIFICATE_UTILS_BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n";
char* ATSC3_A360_CERTIFICATE_UTILS_END_CERTIFICATE = "\n-----END CERTIFICATE-----\n";

char* ATSC3_A360_CERTIFICATES_PEARL_A3SA_ROOT_CERT_SN_0569 = "-----BEGIN CERTIFICATE-----\n"
															 "MIIFZjCCA06gAwIBAgIQfWz8GlbfqolzgvmmywRzPzANBgkqhkiG9w0BAQsFADBM\n"
															 "MQswCQYDVQQGEwJVUzERMA8GA1UEChMIUGVhcmwgVFYxEjAQBgNVBAsTCVJvb3Qg\n"
															 "Q0EtMTEWMBQGA1UEAxMNQVRTQzMgUm9vdC1DQTAgFw0xODA0MTkwMDAwMDBaGA8y\n"
															 "MDY4MDQxODIzNTk1OVowTDELMAkGA1UEBhMCVVMxETAPBgNVBAoTCFBlYXJsIFRW\n"
															 "MRIwEAYDVQQLEwlSb290IENBLTExFjAUBgNVBAMTDUFUU0MzIFJvb3QtQ0EwggIi\n"
															 "MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDjBJrNXMq6TEy6dAaDi5Rr2nNS\n"
															 "ptvkboa2pVkoSwoCD6+OJ5UPMkclFsdIPfGUnEh/jYw/QwcLNrnwoipFV9+ZDbAj\n"
															 "z/xX0ZC6VKmORvjn3gHJ9oyPjWWPyFR7ybykKoy78XCzlnuFSsd6ishJFi8l31x6\n"
															 "tuu/+la11cBOy8h2oTVznMJFP49xcic/BkEMnPEm5p8sUBVtNUeveu9us3Ugp9X6\n"
															 "k7NA/jiWTpUvRYtpActQGrmj2q8+I9XXxkatS5pcI1XwIwmBBp51PW7244PjV875\n"
															 "0nCP8RRrxTCMCWiQX9RIz4wNU+xw3jTIegCnYn+9K0Shgwnj2hpEede2JCQVAPfZ\n"
															 "nZvKIDCfrF0AnDSCKfArBNRu5RyHypiqIf3dvlfVsfjDhCxLHTtyYUV/ryqpIWxe\n"
															 "tHYe3q6WQrJunG3yQjtmiyprDmsy2SgtrugNjj6BFHbiyIl27mZ9wH4NTr1ZYZAy\n"
															 "QO2O2FASc+ddlSpuVL4WNu7QvKPKsHQ+2bXWWxr1KGOydEwRX6F0gqrMI9Ex7p9N\n"
															 "QeDeMCEkO3siEUeP5GfRFh62bkruJjdDnh1+J86Uiy+kJsa+ZplCsXUGsMWAvYBC\n"
															 "/PX4aKhcQsPHSgQFODbemDHSHJqkttrT0f4YrJVFSZHRo6bief1y4QmPDR5xCWlW\n"
															 "ty/tz9T2kOVLEjFflQIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/\n"
															 "BAUwAwEB/zAdBgNVHQ4EFgQUBWnC/LqI8OAc+HJxWAC4ngqAcaYwDQYJKoZIhvcN\n"
															 "AQELBQADggIBAE+hNeww0zMiCyM+5iCNr3HdkkyHuUjCCdHN7ntSMOp9VFtmTW5t\n"
															 "zR9D0hMt5A7gEwwuXH7KabEWueEBOVUqS+cE33M6HBoYNlX57SYPHXgeHNU453+O\n"
															 "/oG6msOAz7O0uwhUXH0UVUZCqbAy7JtRy8AjxqUKl8ulYWaAtHLH+JEsiq1nut80\n"
															 "xAiJLxEOgDK4wkBpmtKV1RjPjeJYwbPaB93KuNbhHJdaelI2uKr5a/uzs/hZfNJ0\n"
															 "Kg+tXTmD69m/x0BBht5LHghpblQ7WNY1lggbPOoExq8kfxigb9OgoUntiVpRj8CP\n"
															 "tUEzulI8HPKNjsqbcUEtT9Dj8VUM7gnEFSvSmwENym1RqR/6VC/lYz80xLA59qb2\n"
															 "B82fJio0SNvmWOIrjutXIDknJ9xK6lc2Tq+FwieIvipfM/rS2O0fdpBP97h4iSWB\n"
															 "0npDuv6Lv3SXkjH01EP+GrmwBzJtsdB3OUtcg3PWNBHUf6Z1O4Gejb5zAUWrbVDX\n"
															 "nxuTYFztc2b/1iI++wcNecIh0YRjxgRP0J0SCtmokLzXO6YkktJGdSQjeIE2sIi9\n"
															 "P7VJdskYHboZk+wySHqCCSlt/f9On5bfsSt4CKgGqjx9SYRD5pYQBHxGbdWGl8Oi\n"
															 "FLQgWEDCLgXyVcLJ/xDJg7K/30FqhoClvivATPOsfZtGcJ+Dra5PM2Z0\n"
															 "-----END CERTIFICATE-----";

/*
 * intermediat signing ca-2
 *
 *    Issuer: C = US, O = Pearl TV, OU = Root CA-1, CN = ATSC3 Root-CA
        Validity
            Not Before: Sep  8 00:00:00 2021 GMT
            Not After : Sep  8 23:59:59 2030 GMT
        Subject: C = US, O = ATSC 3.0 Security Authority LLC, OU = Signing CA-DC1, CN = ATSC 3.0 Signing CA-2
 */

char* ATSC3_A360_CERTIFICATES_PEARL_A3SA_INTERMEDIATE_SIGNING_CA_2_SN_A0D3 = "-----BEGIN CERTIFICATE-----\n"
																			 "MIIF7zCCA9egAwIBAgIQHYHAommgPZqvEoQoWT22uDANBgkqhkiG9w0BAQ0FADBM\n"
																			 "MQswCQYDVQQGEwJVUzERMA8GA1UEChMIUGVhcmwgVFYxEjAQBgNVBAsTCVJvb3Qg\n"
																			 "Q0EtMTEWMBQGA1UEAxMNQVRTQzMgUm9vdC1DQTAeFw0yMTA5MDgwMDAwMDBaFw0z\n"
																			 "MDA5MDgyMzU5NTlaMHAxCzAJBgNVBAYTAlVTMSgwJgYDVQQKEx9BVFNDIDMuMCBT\n"
																			 "ZWN1cml0eSBBdXRob3JpdHkgTExDMRcwFQYDVQQLEw5TaWduaW5nIENBLURDMTEe\n"
																			 "MBwGA1UEAxMVQVRTQyAzLjAgU2lnbmluZyBDQS0yMIIBojANBgkqhkiG9w0BAQEF\n"
																			 "AAOCAY8AMIIBigKCAYEAu7US2OxGzCtEMQZ7FR0fNv6d6hd+x3hV7Uu0H8wso+rX\n"
																			 "br4+WhHmenMLLSS5VT0qchH9Bs8ntS15Ijxvgj8rj1ZzeHY7p9enLp9LnbmC4/Vt\n"
																			 "iRM9W5w4oqCt7rHYG2soYweyoedjyhvXQSZzZPi3gSX5wgjwAINLbPc+1KwL61nP\n"
																			 "Fqwuy8QeEitV9dhR+V5HS3kt7jkIru+aHFvmDhEKRxrZTZ1c1ayEC8AKnwABhTod\n"
																			 "Rpvq14yNuAppStJ71DIIsqZk7H4YcUDSLhbgbGxN6UMWPb+U7zzTIGQBCp297vFC\n"
																			 "OUHjvJvSM5QU3tfZM1QDNkftyIqDohKKBJKQGSODGPOHCkXPPisv9itKaM4gPMh/\n"
																			 "GcZZRwiwt0i+nQwndmleViUGD9LMiDeNnm5z6qIO+YwaV4G+/HKUJ0SpVmA3vH/U\n"
																			 "Pu0Zc0nvk8wvcVZtjdsu6m/ncSMQBjslZ6spgt01OQNGas4ODHyeqt46vdL2MxB8\n"
																			 "bjv0zOa3DwOx2FvbJQnhAgMBAAGjggEnMIIBIzASBgNVHRMBAf8ECDAGAQH/AgEA\n"
																			 "MDUGA1UdIAEB/wQrMCkwCwYJKwYBBAGDlGMCMAwGCisGAQQBg5RjAgEwDAYKKwYB\n"
																			 "BAGDlGMCAjBMBgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vcGtpLWNybC5zeW1hdXRo\n"
																			 "LmNvbS9vZmZsaW5lY2EvUGVhcmxUVkFUU0MzUm9vdENBLmNybDAOBgNVHQ8BAf8E\n"
																			 "BAMCAcYwHQYDVR0OBBYEFKDe/SSQWUgCIZcnf+GWO+KBaMa2MB8GA1UdIwQYMBaA\n"
																			 "FAVpwvy6iPDgHPhycVgAuJ4KgHGmMDgGCCsGAQUFBwEBBCwwKjAoBggrBgEFBQcw\n"
																			 "AYYcaHR0cDovL3BraS1vY3NwLmRpZ2ljZXJ0LmNvbTANBgkqhkiG9w0BAQ0FAAOC\n"
																			 "AgEAEtmDPuS023t4GSaMMtMkPyh8IG5B2HOPtnwjXzf418ar2XCMcaRI7jGk12+V\n"
																			 "POg5S6baCKin+QSgbGonU6mH9eLEhl2fCpRMnM6XhzdplCCj7xMZAHf5AhuCz+M5\n"
																			 "tqaQelVv4WJrWHvMK1Jdw4q6GDtEKxF0cIYXyrinMqR65P2qvjEaJZUNdRSo/yux\n"
																			 "u0UrkbNtuJ9TzQABnY5y7pTgcJOBbGes6bC/VrWurUXDFpeNfybm5PRZE9rlsIIe\n"
																			 "T4J+3i7BGpUdnrPWQrk6NNa6M36XKxe1dh1HptyNXwOPamS5qpw7ewQARlP495uO\n"
																			 "RvAM3p50TN2vtXKLgDQENi+Kmo/E+ORKaLJtgbet0jllhR9L7Gau8DdykvnTHkm2\n"
																			 "/yxB0tDZTbrTRJciPjFHsRXmYQAyQYaod729shWngSgNE08n4RkiVSsSFbhrCXh+\n"
																			 "ZrCF9wBpfCVoDaLemjriVy4SK7Hxmr39XxF66B9fBnGLXMvgyYRymNWPyys5j/wl\n"
																			 "+iZt4KTm5W5iOhdIXaJxOO6b+EFeNZsDi8p52nvi5L5rtxw/1GAIiz39RTGd/w2t\n"
																			 "hKQ+USVa7zY5sllzUBMjepeog/OOPwtbGccP38U6oW8vL00bQGbW5HuWP58qGcY9\n"
																			 "Wk6I1mhinOmrpm1BsHqdYVFDCJZqQK4XMNukaxP6ey6xmJg=\n"
																			 "-----END CERTIFICATE-----";
// 2022-09-01 - this is old, do not use
char* __OLD_ATSC3_CMS_UTILS_CDT_A3SA_ROOT_2020_CERT = "-----BEGIN CERTIFICATE-----\n"
													  "MIIF1DCCA7ygAwIBAgIJAJs5WkwMaeOYMA0GCSqGSIb3DQEBCwUAMEkxCzAJBgNV\n"
													  "BAYTAlVTMQ0wCwYDVQQKEwRBM1NBMRIwEAYDVQQLEwlSb290IDIwMjAxFzAVBgNV\n"
													  "BAMTDkEzU0EgUm9vdCAyMDIwMB4XDTIwMDkxODAxNTgwN1oXDTI1MDkxNzAxNTgw\n"
													  "N1owSTELMAkGA1UEBhMCVVMxDTALBgNVBAoTBEEzU0ExEjAQBgNVBAsTCVJvb3Qg\n"
													  "MjAyMDEXMBUGA1UEAxMOQTNTQSBSb290IDIwMjAwggIiMA0GCSqGSIb3DQEBAQUA\n"
													  "A4ICDwAwggIKAoICAQC5pRHyGDO5tmWjQ/xc3/7k15CdrAzWsSvwTnHnufesotdX\n"
													  "ILJ4WcsQIXLGHrmAUH9tpzTzO618XbVcQOMUE7haWi3tEH0P0KYW7Lt5NLeaAahl\n"
													  "PxWq574/gEdxVTbqgGIzkerlzHjnJ+XEyxtKhBX26kgT5OplrIXNWddZuxZmiy8F\n"
													  "n9lARmA4R+rJ8AbU24wvQ6zxFaEAM1WElRtMx+5XY9SVTXrA+iLAe3FuBRgsrF2p\n"
													  "lB9KQmr/wgK4cDUmz6Z6WS1slmfkMk8+/faoVPlJOLvakCUEXuNw8wIo2NqEQWV3\n"
													  "zr8jsZ5PJapv03TRUeeruq2ise9JR4LY1ofhzZk+rYmZAqa+azzaW0ZVX4DP+3ez\n"
													  "ijR0fI2GTiXggUy2YiDQKKpk3NZ5wI2yJQpAeeR1zzyn50eb7LS8QaUo0TR9lSuw\n"
													  "kDNipi0T1ipH/p7QsqzKgxsaW5l/l3V8Xn6jkBWG1OQ5yDv9HqL51u9UGZoGS1Ea\n"
													  "OUVxBowIchjH8I4EIYx+EKOFYibCsDX6oPj4rg9r4EBkQDW8z4GzM4g8M7/g206z\n"
													  "kT6Mg84eONdtl9Z3JN2xQNqL7/5UNzd1xu7KCoIJeEU9MU3b55R+LkhHDRK99KqZ\n"
													  "bW5mjs+HwUswaz1eLOlY0jpSZI1gF0gLobpoI8UJKlOroF1dei6VdFfsnhBgQwID\n"
													  "AQABo4G+MIG7MB0GA1UdDgQWBBQz08VmTiXPIaQruOX0oK2AL213qzB5BgNVHSME\n"
													  "cjBwgBQz08VmTiXPIaQruOX0oK2AL213q6FNpEswSTELMAkGA1UEBhMCVVMxDTAL\n"
													  "BgNVBAoTBEEzU0ExEjAQBgNVBAsTCVJvb3QgMjAyMDEXMBUGA1UEAxMOQTNTQSBS\n"
													  "b290IDIwMjCCCQCbOVpMDGnjmDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE\n"
													  "AwIBhjANBgkqhkiG9w0BAQsFAAOCAgEAkLkgq4/AUuBLGHHox07fRVK3DEha7RCL\n"
													  "Jv4NwvRU8ydQXs1Mt9nOlwA5uTZCqN/qu92N6z6hNv4mi6OqzVNB4nxHQm0rV+bG\n"
													  "X4IkVdjukD5UPQ5UDfPXB4KP8fgpSzdgqeNl7tcLXFW/ZkCvTxCQdOMTQ8J3BEsK\n"
													  "qH5t7pi7O3oFHVJ8YVE3FuAM9WzGxFHAh4Sl7p90moeuky28wzoAiBsyCYBQfJGG\n"
													  "Cqj4J/yKzFlx5Zh+TGxMWwGaXW6iEzp8G0PWEnE/mMniF3B6Y6T2sygx/rdVgrD0\n"
													  "aWj/1bJJyqQIM+wU1Nfy9xMNSSOSyg9f42epPCkac1KmZ2bw9/Ewd/kokBiSj/lo\n"
													  "F07/fRxWVxZDpNKznJTs3E7YjwqhK3yx57LBkgaiIprBO0txwnTYOafYTBNkRD5S\n"
													  "p7qevNqJ0dEuM5xwByo2B2OIxd1y/77Z5/6Z9ZzoxAlfNee3ksU+5juFihsVvuuW\n"
													  "Dsyw7EFlSMl7IhymGvIluM4GgxI+1vOu8RSXGigtst/68Ib6tEBjlLlu3SZgKDPV\n"
													  "gFFaCTOngQeDTakhA7NisXnzES0IY4XDhYx5REzBAzYB5kxzotbIobRvVlbzP8fQ\n"
													  "NQjAyIDB2Q/M+0hbbx1TYB4j9PQ0MTN/ZDp7Hr3n4a4hpkcNSPXsBAmGPUJdYaUh\n"
													  "siGVF4KJUIw=\n"
													  "-----END CERTIFICATE-----";



static int debug_run_count = 0;
//end hack


/* Initialize the protocol and registered fields */
/* ============================================= */

void proto_register_atsc3_lls(void);
void proto_reg_handoff_atsc3_lls(void);

static wmem_array_t* certificate_table = NULL;

static int proto_atsc3_lls = -1;
static int proto_xml = -1;

static int hf_lls_table_id = -1;
static int hf_lls_group_id = -1;
static int hf_lls_group_count_minus1 = -1;
static int hf_lls_table_version = -1;

static int hf_payload = -1;
static int hf_payload_str = -1;

static int hf_lls_signedmultitable_lls_payload_count = -1;
static int hf_lls_signedmultitable_lls_payload_id = -1;
static int hf_lls_signedmultitable_lls_payload_version = -1;
static int hf_lls_signedmultitable_lls_payload_length = -1;
static int hf_lls_signedmultitable_signature_length = -1;
static int hf_lls_signedmultitable_signature_bytes = -1;

static int hf_lls_signedmultitable_signature_valid = -1;
static int hf_lls_signedmultitable_signature_invalid = -1;


static int ett_main = -1;
static int ett_certificationdata = -1;
static int ett_signedmultitable = -1;

static expert_field ei_payload_decompress_failed = EI_INIT;

static dissector_handle_t xml_handle;
static dissector_handle_t rmt_lct_handle;
static dissector_handle_t rmt_fec_handle;

static dissector_handle_t atsc3_route_dissector_handle;
static dissector_handle_t atsc3_mmtp_dissector_handle;
conversation_t* conv_mmt = NULL;


guint32 added_lls_table_slt_version_conversations = 0;
gboolean has_added_lls_table_slt_version_conversations = FALSE;

guint32 added_lls_table_certificationdata_version = 0;
gboolean has_added_lls_table_certificationdata = FALSE;


static char* strlcopy(const char* src) {
	size_t len = strnlen(src, 16384);
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

	guint32     	lls_table_id = -1;
	guint32     	lls_group_id = -1;
	guint32     	lls_group_count_minus_1 = -1;
    guint32			lls_table_version = -1;

    int             len;

    /* Offset for subpacket dissection */
    guint offset = 0;

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *lls_tree;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATSC3 LLS");
    col_clear(pinfo->cinfo, COL_INFO);


    /* Create subtree for LLS  */
    ti = proto_tree_add_item(tree, proto_atsc3_lls, tvb, offset, -1, ENC_NA);
    lls_tree = proto_item_add_subtree(ti, ett_main);



 /* Fill the LLS subtree */
	lls_table_id = tvb_get_guint8(tvb, offset);

	proto_tree_add_item_ret_uint(lls_tree, hf_lls_table_id, tvb, offset++, 1, ENC_BIG_ENDIAN, &lls_table_id);
	proto_tree_add_item_ret_uint(lls_tree, hf_lls_group_id, tvb, offset++, 1, ENC_BIG_ENDIAN, &lls_group_id);
	proto_tree_add_item_ret_uint(lls_tree, hf_lls_group_count_minus1, tvb, offset++, 1, ENC_BIG_ENDIAN, &lls_group_count_minus_1);
	proto_tree_add_item_ret_uint(lls_tree, hf_lls_table_version, tvb, offset++, 1, ENC_BIG_ENDIAN, &lls_table_version);


    /* Add the Payload item */
    if (tvb_reported_length(tvb) > offset){
		guint32 lls_table_length = tvb_captured_length_remaining(tvb, offset);

		atsc3_lls_process_table(ti, lls_tree, tvb, pinfo, offset, lls_table_id, lls_group_id, lls_group_count_minus_1, lls_table_version, lls_table_length);

    }

    return tvb_reported_length(tvb);
}


guint atsc3_lls_process_table(proto_item* ti, proto_tree* lls_tree, tvbuff_t *tvb, packet_info *pinfo, guint offset, guint32 lls_table_id, guint32 lls_group_id, guint32 lls_group_count_minus_1, guint32 lls_table_version, guint32 lls_table_length) {

    xml_frame_t*	xml_frame;
    xml_frame_t*	xml_dissector_frame;
    tvbuff_t*		new_tvb;

	col_append_fstr(pinfo->cinfo, COL_INFO, "%s: version: %d, ", val_to_str(lls_table_id, atsc3_lls_table_strings, "Unknown lls_table_id: %d"), lls_table_version);

	switch(lls_table_id) {

		case ATSC3_LLS_ServiceLocationTable:
		case ATSC3_LLS_RegionRatingTable:
		case ATSC3_LLS_SystemTimeTable:
		case ATSC3_LLS_AdvancedEmergencyAlertingTable:
		case ATSC3_LLS_OnscreenMessageNotification:
		case ATSC3_LLS_UserDefined:
		{

			//uncompress and display

			//col_append_fstr
			tvbuff_t *next_tvb;
			next_tvb = tvb_uncompress(tvb, offset, lls_table_length);
			if (next_tvb) {
				add_new_data_source(pinfo, next_tvb, "compressed data");
				proto_tree_add_item(lls_tree, hf_payload_str, next_tvb, 0, -1, ENC_STRING);

				if(lls_table_id == 0x01) {
					call_dissector_with_data(xml_handle, next_tvb, pinfo, lls_tree, NULL);

					xml_dissector_frame = (xml_frame_t *)p_get_proto_data(pinfo->pool, pinfo, proto_xml, 0);
					if(xml_dissector_frame == NULL) {
						return tvb_captured_length(tvb);
					} else {

						if(!has_added_lls_table_slt_version_conversations || (has_added_lls_table_slt_version_conversations && added_lls_table_slt_version_conversations != lls_table_version)) {
							atsc3_lls_slt_add_conversations_from_xml_dissector(xml_dissector_frame);
							has_added_lls_table_slt_version_conversations = TRUE;
							added_lls_table_slt_version_conversations = lls_table_version;
						}
					}
				} else {
					call_dissector(xml_handle, next_tvb, pinfo, lls_tree);
				}


			} else {
				expert_add_info(pinfo, ti, &ei_payload_decompress_failed);

			}
			offset += lls_table_length;

			break;
		}

		case ATSC3_LLS_CertificationData:
		{

			//Cert

	        proto_tree *certificationdata_tree = proto_tree_add_subtree(lls_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_certificationdata, NULL, "CertificationData");

	        //jjustman-2022-10-08 - todo - persist into wmem_file_scope for CertificationData.ToBeSignedData.Certificates[n]

	    	tvbuff_t *next_tvb;
			next_tvb = tvb_uncompress(tvb, offset, lls_table_length);
			if (next_tvb) {
				add_new_data_source(pinfo, next_tvb, "compressed data");
				proto_tree_add_item(lls_tree, hf_payload_str, next_tvb, 0, -1, ENC_STRING);

				call_dissector_with_data(xml_handle, next_tvb, pinfo, lls_tree, NULL);

				xml_dissector_frame = (xml_frame_t *)p_get_proto_data(pinfo->pool, pinfo, proto_xml, 0);
				if(xml_dissector_frame == NULL) {
					return tvb_captured_length(tvb);
				} else {

					if(!has_added_lls_table_certificationdata || (has_added_lls_table_certificationdata && added_lls_table_certificationdata_version != lls_table_version)) {
						g_debug("parsing lls_table_certificationdata: %d", lls_table_version);
						//TODO
						atsc3_lls_certificationdata_persist_certificates_from_xml_dissector(xml_dissector_frame);

						has_added_lls_table_certificationdata = TRUE;
						added_lls_table_certificationdata_version = lls_table_version;
					}
				}
			}

			break;
		}

		case ATSC3_LLS_SignedMultiTable:
		{

			guint32 smt_lls_payload_count = 0;
			guint32 smt_signature_length= 0;
			guint	smt_payload_start_tvb_offset = offset;
			guint	smt_payload_end_tvb_offset = 0;

	        proto_tree *signedmultitable_tree = proto_tree_add_subtree(lls_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_signedmultitable, NULL, "SignedMultiTable");


			proto_tree_add_item_ret_uint(signedmultitable_tree, hf_lls_signedmultitable_lls_payload_count, tvb, offset, 1, ENC_BIG_ENDIAN, &smt_lls_payload_count);
			offset++;

			for(guint32 i=0; i < smt_lls_payload_count; i++) {
				guint32 lls_payload_id_smt = 0;
				guint32 lls_payload_version_smt = 0;
				guint32 lls_payload_length_smt = 0;

		        proto_tree *signedmultitable_instance_tree = proto_tree_add_subtree(signedmultitable_tree, tvb, offset, tvb_captured_length_remaining(tvb, offset), ett_signedmultitable, NULL, "Table");

				proto_tree_add_item_ret_uint(signedmultitable_instance_tree, hf_lls_signedmultitable_lls_payload_id, tvb, offset, 1, ENC_BIG_ENDIAN, &lls_payload_id_smt);
				offset++;
				proto_tree_add_item_ret_uint(signedmultitable_instance_tree, hf_lls_signedmultitable_lls_payload_version, tvb, offset, 1, ENC_BIG_ENDIAN, &lls_payload_version_smt);
				offset++;
				proto_tree_add_item_ret_uint(signedmultitable_instance_tree, hf_lls_signedmultitable_lls_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN, &lls_payload_length_smt);
				offset+=2;

				//offset should be += lls_payload_length_smt
				offset = atsc3_lls_process_table(ti, signedmultitable_instance_tree, tvb, pinfo, offset, lls_payload_id_smt, lls_group_id, lls_group_count_minus_1, lls_payload_version_smt, lls_payload_length_smt);

			}
			smt_payload_end_tvb_offset = offset;

			proto_tree_add_item_ret_uint(signedmultitable_tree, hf_lls_signedmultitable_signature_length, tvb, offset, 2, ENC_BIG_ENDIAN, &smt_signature_length);
			offset+=2;
			proto_tree_add_item(signedmultitable_tree, hf_lls_signedmultitable_signature_bytes, tvb, offset, smt_signature_length, ENC_BIG_ENDIAN);

#ifdef HAVE_OPENSSL
			gboolean cms_signature_valid = FALSE;
			guint smt_payload_length = smt_payload_end_tvb_offset - smt_payload_start_tvb_offset;
		    guchar* smt_payload = (guchar*)wmem_alloc(pinfo->pool, smt_payload_length);
		    guchar* smt_signature = (guchar*)wmem_alloc(pinfo->pool, smt_signature_length);

	    	//only process if we have a persisted certificate table...
		    if(certificate_table) {

		    	guint certificate_table_count = wmem_array_get_count(certificate_table);

		    	BIO 	*signature_binary_der_in = NULL;
		    	BIO 	*payload_binary_in = NULL;

		    	//for smime validation
		    	BIO 	*signed_multipart_payload_in = NULL;
		    	BIO 	*extracted_smime_payload = NULL;

		    	BIO 	*extracted_payload_out = NULL;
		    	long 	extracted_payload_out_len = 0;

		    	X509_STORE 	*st_root = NULL;
		    	X509 		*cacert_root = NULL;
		    	X509 		*cacert_intermediate = NULL;

		    	STACK_OF(X509) *pcerts = NULL;
		    	CMS_ContentInfo *cms = NULL;

		    	unsigned int cms_verify_flags = 0;

		    	int ret = 1;

		    	typedef struct to_free_bio_and_x509_refs_s {
		    		guchar* fixup_cdt_table_block;
		    		BIO*	bio_ptr;
		    		X509*	x509_ptr;
		    	} to_free_bio_and_509_refs_t;

		    	to_free_bio_and_509_refs_t* to_free_bio_and_509_refs = calloc(certificate_table_count, sizeof(to_free_bio_and_509_refs_t));


		    	//duplicate code warning

		    	st_root = X509_STORE_new();
		    	X509_STORE_set_purpose(st_root, X509_PURPOSE_ANY);

		    	/*
		    	 * add our:
		    	 * 	ATSC3_A360_CERTIFICATES_PEARL_A3SA_ROOT_CERT_SN_0569 and
		    	 * 	ATSC3_A360_CERTIFICATES_PEARL_A3SA_INTERMEDIATE_SIGNING_CA_2_SN_A0D3
		    	 *
		    	 */
		    	BIO* cacert_root_bio = BIO_new_mem_buf(ATSC3_A360_CERTIFICATES_PEARL_A3SA_ROOT_CERT_SN_0569, (int)strlen(ATSC3_A360_CERTIFICATES_PEARL_A3SA_ROOT_CERT_SN_0569));

		    	cacert_root = PEM_read_bio_X509(cacert_root_bio, NULL, 0, NULL);
		    	 if (!cacert_root) {
		    		goto err;
		    	 }

		    	 if (!X509_STORE_add_cert(st_root, cacert_root)) {
		    		goto err;
		    	 }

		    	BIO * cacert_ca_chain_signing_ca_2 = BIO_new_mem_buf(ATSC3_A360_CERTIFICATES_PEARL_A3SA_INTERMEDIATE_SIGNING_CA_2_SN_A0D3, (int)strlen(ATSC3_A360_CERTIFICATES_PEARL_A3SA_INTERMEDIATE_SIGNING_CA_2_SN_A0D3));
		    	cacert_intermediate = PEM_read_bio_X509(cacert_ca_chain_signing_ca_2, NULL, 0, NULL);
		    	if (!cacert_intermediate) {
		    		goto err;
		    	}

		    	if (!X509_STORE_add_cert(st_root, cacert_intermediate)) {
		    		goto err;
		    	}

		    	pcerts = sk_X509_new_null();


				tvb_memcpy(tvb, smt_payload, smt_payload_start_tvb_offset, smt_payload_length);

#ifdef __JJ_PACKET_INVALID_EVERY_N
				if((pinfo->num % 10) == 0) {
					smt_payload[1] = 0xFF;
				}
#endif
				tvb_memcpy(tvb, smt_signature, offset, smt_signature_length);
				g_debug("have openssl, smt_payload: %p, len: %d, smt_signature: %p, len: %d\n", smt_payload, smt_payload_length, smt_signature, smt_signature_length);


				for(guint i=0; i < certificate_table_count; i++) {
		    		atsc3_lls_certificationdata_certificate_t* atsc3_lls_certificationdata_certificate = NULL;
		    		atsc3_lls_certificationdata_certificate = wmem_array_index(certificate_table, i);
		    		if(atsc3_lls_certificationdata_certificate) {

		    			guint begin_cert_len = (guint)strlen(ATSC3_A360_CERTIFICATE_UTILS_BEGIN_CERTIFICATE);
		    			guint my_cert_len = (guint)strlen(atsc3_lls_certificationdata_certificate->certificate_base64);
		    			guint end_cert_len = (guint)strlen(ATSC3_A360_CERTIFICATE_UTILS_END_CERTIFICATE);

		    			guint my_cert_total_len = begin_cert_len + my_cert_len + end_cert_len;

		    			guchar* my_cert_from_cdt = calloc(my_cert_total_len + 1, sizeof(guchar));

		    			memcpy(my_cert_from_cdt, ATSC3_A360_CERTIFICATE_UTILS_BEGIN_CERTIFICATE, begin_cert_len);
		    			memcpy(my_cert_from_cdt + begin_cert_len, atsc3_lls_certificationdata_certificate->certificate_base64, my_cert_len);
		    			memcpy(my_cert_from_cdt + begin_cert_len + my_cert_len, ATSC3_A360_CERTIFICATE_UTILS_END_CERTIFICATE, end_cert_len);


		                BIO * to_be_signed_payload = BIO_new_mem_buf(my_cert_from_cdt, my_cert_total_len);
		                X509* to_be_signed_x509 = PEM_read_bio_X509(to_be_signed_payload, NULL, 0, NULL);

		                //for memory cleanup...
		                to_free_bio_and_509_refs[i].fixup_cdt_table_block = my_cert_from_cdt;
		                to_free_bio_and_509_refs[i].bio_ptr = to_be_signed_payload;
		                to_free_bio_and_509_refs[i].x509_ptr = to_be_signed_x509;

		                if (!to_be_signed_x509) {
		                	g_warning("atsc3_cms_validate_from_context: index: %d failed to parse as PEM_read_bio_X509! to_be_signed_payload: %p",
		                                          i, to_be_signed_payload);
		                    goto err;
		                }

		                sk_X509_push(pcerts, to_be_signed_x509);

		                g_debug("cert_t: %p, id: %d, ptr: %p, value: %s\n", atsc3_lls_certificationdata_certificate, atsc3_lls_certificationdata_certificate->index, atsc3_lls_certificationdata_certificate->certificate_base64, atsc3_lls_certificationdata_certificate->certificate_base64);
						//append to openssl cert x509
					} else {
						g_warning("certificate table index: %d is NULL!", i);
					}
				}


				signature_binary_der_in = BIO_new_mem_buf(smt_signature, smt_signature_length);
				g_debug("atsc3_cms_validate_from_context: Signature DER and Payload: BIO_new_mem_buf: signature_binary_der_in in: %p, smt_signature_length: %d",
									   signature_binary_der_in, smt_signature_length);

				if (!signature_binary_der_in) {
					goto err;
				}

				/* parse DER signature portion of the CMS message */

				cms = d2i_CMS_bio(signature_binary_der_in, &cms);

				if (!cms) {
					g_warning("atsc3_cms_validate_from_context:CMS_read_CMS: failed!");
					goto err;
				}



				payload_binary_in = BIO_new_mem_buf(smt_payload, smt_payload_length);
				g_debug("atsc3_cms_validate_from_context: BIO_new_mem_buf: payload_binary_in in: %p, smt_payload_length: %d, smt_payload:\n%s",
									   payload_binary_in, smt_payload_length, smt_payload);

				if (!payload_binary_in) {
					goto err;
				}


				if (!cms) {
					g_warning("atsc3_cms_validate_from_context:CMS_read_CMS: failed!");
				   goto err;
				}

				extracted_payload_out = BIO_new(BIO_s_mem());

				if (!extracted_payload_out)
				   goto err;

//						//https://www.openssl.org/docs/man1.1.0/man3/CMS_verify.html
//						//will still fail if there are no signers in the CA chain, i.e. only root is not good enough to pass..
//						if(atsc3_cms_validation_context->cms_no_content_verify) {
//							cms_verify_flags = CMS_BINARY | CMS_NOVERIFY | CMS_NO_SIGNER_CERT_VERIFY | CMS_NOCRL | CMS_NO_ATTR_VERIFY | CMS_NO_CONTENT_VERIFY;
//						} else if(atsc3_cms_validation_context->cms_noverify) {
//							cms_verify_flags = CMS_BINARY | CMS_NOVERIFY | CMS_NO_SIGNER_CERT_VERIFY | CMS_NOCRL | CMS_NO_ATTR_VERIFY;
//						} else {
							cms_verify_flags = CMS_BINARY;
					//	}

				proto_item* is_cms_valid = NULL;
				if (!CMS_verify(cms, pcerts, st_root, payload_binary_in, extracted_payload_out, cms_verify_flags)) {
					g_warning("atsc3_cms_validate_from_context:CMS_verify: verification failure");
					is_cms_valid = proto_tree_add_string(signedmultitable_tree, hf_lls_signedmultitable_signature_invalid, tvb, 0, 0, "INVALID");
					col_append_str(pinfo->cinfo, COL_INFO, " CMS: INVALID");
					cms_signature_valid = FALSE;
							//atsc3_cms_validation_context->cms_signature_valid = false;
				} else {
					g_info("atsc3_cms_validate_from_context: verification successful");
					is_cms_valid = proto_tree_add_string(signedmultitable_tree, hf_lls_signedmultitable_signature_valid, tvb, 0, 0, "Valid");
					col_append_str(pinfo->cinfo, COL_INFO, " CMS: Valid");

					cms_signature_valid = TRUE;
						//copy this to our context->cms_entity->cms_verified_extracted_mime_entity
//					char *extracted_payload_out_char_p = NULL;
//					extracted_payload_out_len = BIO_get_mem_data(extracted_payload_out, &extracted_payload_out_char_p);
//
//					atsc3_cms_validation_context->atsc3_cms_entity->cms_verified_extracted_payload = block_Alloc(extracted_payload_out_len);
//					block_Write(atsc3_cms_validation_context->atsc3_cms_entity->cms_verified_extracted_payload, (uint8_t*) extracted_payload_out_char_p, extracted_payload_out_len);
//					block_Rewind(atsc3_cms_validation_context->atsc3_cms_entity->cms_verified_extracted_payload);
//
//					_ATSC3_CMS_UTILS_DEBUG("atsc3_cms_validate_from_context: BIO_get_mem_data: extracted_payload_out_len: %d, extracted_payload_out_char_p:\n%s",
//										   atsc3_cms_validation_context->atsc3_cms_entity->cms_verified_extracted_payload->p_size,
//										   atsc3_cms_validation_context->atsc3_cms_entity->cms_verified_extracted_payload->p_buffer);
				}

				proto_item_set_generated(is_cms_valid);



		err:

				if (!cms_signature_valid) {
					g_warning("atsc3_cms_validate_from_context: error verifying data, errors:");

			#ifdef ATSC3_CMS_UTILS_DUMP_PAYLOADS_FOR_OPENSSL_DEBUGGING
					if(atsc3_cms_validation_context->atsc3_cms_entity->signature) {
						block_Write_to_filename(atsc3_cms_validation_context->atsc3_cms_entity->signature, "raw_binary_payload_signature.der");
					}

					if(atsc3_cms_validation_context->atsc3_cms_entity->raw_binary_payload) {
						block_Write_to_filename(atsc3_cms_validation_context->atsc3_cms_entity->raw_binary_payload, "raw_binary_payload.data");
					}
			#endif
					//ERR_print_errors_fp(stdout);
					//atsc3_cms_validation_context_return = NULL;
				}

				//cleanup in reverse order
				if(cms) {
					CMS_ContentInfo_free(cms);
				}

				if(extracted_payload_out) {
					BIO_free(extracted_payload_out);
				}

				if(extracted_smime_payload) {
					BIO_free(extracted_smime_payload);
				}

				if(signed_multipart_payload_in) {
					BIO_free(signed_multipart_payload_in);
				}

				if(payload_binary_in) {
					BIO_free(payload_binary_in);
				}

				if(signature_binary_der_in) {
					BIO_free(signature_binary_der_in);
				}

				//clear out our intermediates/entity certs

				if(to_free_bio_and_509_refs) {
					for(guint i=0; i < certificate_table_count; i++) {
						if(to_free_bio_and_509_refs[i].fixup_cdt_table_block) {
							free(to_free_bio_and_509_refs[i].fixup_cdt_table_block);
						}
						if(to_free_bio_and_509_refs[i].bio_ptr) {
							BIO_free(to_free_bio_and_509_refs[i].bio_ptr);
							to_free_bio_and_509_refs[i].bio_ptr = NULL;
						}
						if(to_free_bio_and_509_refs[i].x509_ptr) {
							X509_free(to_free_bio_and_509_refs[i].x509_ptr);
							to_free_bio_and_509_refs[i].x509_ptr = NULL;
						}
					}
					free(to_free_bio_and_509_refs);
					to_free_bio_and_509_refs = NULL;
				}

				if(cacert_ca_chain_signing_ca_2) {
					BIO_free(cacert_ca_chain_signing_ca_2);
				}

				if(cacert_intermediate) {
					X509_free(cacert_intermediate);
				}

				if(cacert_root_bio) {
					BIO_free(cacert_root_bio);
				}

				if(cacert_root) {
					X509_free(cacert_root);
				}


				if(st_root) {
					X509_STORE_free(st_root);
				}

		    }


	#else
			g_warning("missing openssl");
	#endif

			break;
		}

		default:
		{
			proto_tree_add_item(lls_tree, hf_payload, tvb, offset, -1, ENC_NA);

			break;
		}

	}
	return offset;
}

void atsc3_lls_slt_add_conversations_from_xml_dissector(xml_frame_t* xml_dissector_frame) {

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
					//jjustman-2022-09-13 - not valid in msvc char slsProtocolString[slsProtocolXml->value->length + 1];
					//memset(slsProtocolString, 0, slsProtocolXml->value->length + 1);

					char* slsProtocolString = calloc(1, slsProtocolXml->value->length + 1);

					memcpy(slsProtocolString, slsProtocolXml->value->real_data, slsProtocolXml->value->length);

					slsProtocol = atoi(slsProtocolString);
					free(slsProtocolString);
				}

				if(slsDestinationIpAddressXml) {
					//char destIpAddress[slsDestinationIpAddressXml->value->length + 1];
					//memset(destIpAddress, 0, slsDestinationIpAddressXml->value->length + 1);

					char* destIpAddress = calloc(1, slsDestinationIpAddressXml->value->length + 1);

					memcpy(destIpAddress, slsDestinationIpAddressXml->value->real_data, slsDestinationIpAddressXml->value->length);
					slsDestinationIpAddress = parseIpAddressIntoIntval(destIpAddress);

					free(destIpAddress);
				}

				if(slsDestinationUdpPortXml) {
					//char destPort[slsDestinationUdpPortXml->value->length + 1];
					//memset(&destPort, 0, slsDestinationUdpPortXml->value->length + 1);
					char* destPort = calloc(1, slsDestinationUdpPortXml->value->length + 1);

					memcpy(destPort, slsDestinationUdpPortXml->value->real_data, slsDestinationUdpPortXml->value->length);
					slsDestinationPort = parsePortIntoIntval(destPort);
					free(destPort);
				}

				if(slsSourceIpAddressXml) {
					//char sourceIpAddress[slsSourceIpAddressXml->value->length + 1];
					//memset(&sourceIpAddress, 0, slsSourceIpAddressXml->value->length + 1);
					char* sourceIpAddress = calloc(1, slsSourceIpAddressXml->value->length + 1);

					memcpy(sourceIpAddress, slsSourceIpAddressXml->value->real_data, slsSourceIpAddressXml->value->length);
					slsSourceIpAddress = parseIpAddressIntoIntval(sourceIpAddress);
					free(sourceIpAddress);
				}

				conversation_t* conv_route = NULL;

				address addr_1;
				guint32 v4_addr_1 = htonl(slsSourceIpAddress);
				set_address(&addr_1, AT_IPv4, 4, &v4_addr_1);

				address addr_2;
				guint32 v4_addr_2 = htonl(slsDestinationIpAddress);
				set_address(&addr_2, AT_IPv4, 4, &v4_addr_2);

#ifdef __JJ_MATCH_SRC_LLS_IP_ADDR
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
#else


				if(slsProtocol == 1) {
					// add ROUTE dissector


					conv_route = conversation_new(1, &addr_2, NULL, ENDPOINT_UDP, slsDestinationPort, 0, NO_ADDR2 | NO_PORT2);

					conversation_add_proto_data(conv_route,  proto_atsc3_route, NULL);
					conversation_set_dissector(conv_route, atsc3_route_dissector_handle);

				} else if(slsProtocol == 2) {
					//add MMT dissector

					//conv_mmt = conversation_new(1, &addr_1, &addr_2, ENDPOINT_UDP, 0, slsDestinationPort, 0);
					conv_mmt = conversation_new(1, &addr_2, NULL, ENDPOINT_UDP, slsDestinationPort, 0, NO_ADDR2 | NO_PORT2);


					//conv_mmt = conversation_new(1, &addr_1, &addr_2, ENDPOINT_UDP, 52581, slsDestinationPort, 0);
					//, NO_ADDR2 | NO_PORT2);

					conversation_add_proto_data(conv_mmt,  proto_atsc3_mmtp, NULL);
					conversation_set_dissector(conv_mmt, atsc3_mmtp_dissector_handle);

				}

#endif


			}

			service = __internal_xml_get_tag(service->next_sibling, "Service");


		}
	}

}




void atsc3_lls_certificationdata_persist_certificates_from_xml_dissector(xml_frame_t* xml_dissector_frame) {

	//super-hack: TODO: fixme!

	if(certificate_table) {
		wmem_destroy_array(certificate_table);
	}
	certificate_table = wmem_array_new(wmem_file_scope(), sizeof(atsc3_lls_certificationdata_certificate_t));


	xml_frame_t* certificationData_element = xml_dissector_frame->first_child->next_sibling; //xml_get_tag(xml_dissector_frame, "slt");
	xml_frame_t* toBeSignedData_element = NULL;

	xml_frame_t* certificate = NULL;

	guint32 certificate_count = 0;

	if(certificationData_element) {

		toBeSignedData_element = __internal_xml_get_first_child_tag(certificationData_element, "ToBeSignedData");

		certificate = __internal_xml_get_first_child_tag(toBeSignedData_element, "Certificates");

		while(certificate) {
			if(certificate && certificate->first_child && certificate->first_child->value && certificate->first_child->value->real_data) {
				//hack...
				tvbuff_t* my_data = certificate->first_child->value;
				atsc3_lls_certificationdata_certificate_t* atsc3_lls_certificationdata_certificate = wmem_alloc(wmem_file_scope(), sizeof(atsc3_lls_certificationdata_certificate_t));

				atsc3_lls_certificationdata_certificate->index = certificate_count;
				atsc3_lls_certificationdata_certificate->certificate_base64 = wmem_alloc(wmem_file_scope(), my_data->length + 1);
				memset(atsc3_lls_certificationdata_certificate->certificate_base64, 0, my_data->length+1);

				memcpy(atsc3_lls_certificationdata_certificate->certificate_base64, my_data->real_data, my_data->length);

				g_debug("cert_t: %p, id: %d, ptr: %p, value: %s\n", atsc3_lls_certificationdata_certificate, atsc3_lls_certificationdata_certificate->index, atsc3_lls_certificationdata_certificate->certificate_base64, atsc3_lls_certificationdata_certificate->certificate_base64);
				wmem_array_append(certificate_table, atsc3_lls_certificationdata_certificate, 1);

				certificate_count++;
			}

			certificate = __internal_xml_get_tag(certificate->next_sibling, "Certificates");
		}
#ifdef __JJ_DEBUG
    	guint certificate_table_count = wmem_array_get_count(certificate_table);
    	for(guint i=0; i < certificate_table_count; i++) {
			//guchar* my_certificate = wmem_array_index(certificate_table, i);
    		atsc3_lls_certificationdata_certificate_t* atsc3_lls_certificationdata_certificate = NULL;
    		atsc3_lls_certificationdata_certificate = wmem_array_index(certificate_table, i);
    		if(atsc3_lls_certificationdata_certificate) {
    			g_debug("cert_t: %p, id: %d, ptr: %p, value: %s\n", atsc3_lls_certificationdata_certificate, atsc3_lls_certificationdata_certificate->index, atsc3_lls_certificationdata_certificate->certificate_base64, atsc3_lls_certificationdata_certificate->certificate_base64);
				//append to openssl cert x509
			} else {
				g_debug("certificate table index: %d is NULL!", i);
			}
		}
#endif
	}
}





void proto_register_atsc3_lls(void)
{
    /* Setup ALC header fields */
    static hf_register_info hf_ptr[] = {

        { &hf_lls_table_id,  							{ "LLS Table ID", 				"lls.table_id", 				FT_UINT8, BASE_DEC, atsc3_lls_table_strings, 0x0, NULL, HFILL }},
		{ &hf_lls_group_id, 							{ "LLS Group ID", 				"lls.group_id",					FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_lls_group_count_minus1, 					{ "LLS Group Count minus1", 	"lls.group_count", 				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_lls_table_version, 						{ "LLS Table Version", 			"lls.table_version", 			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_payload,      							{ "Payload", 					"lls.table_payload_bytes", 		FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_payload_str,  							{ "Payload", 					"lls.table_xml", 				FT_STRING, STR_ASCII, NULL, 0x0, NULL, HFILL }},

        //smt support
		{ &hf_lls_signedmultitable_lls_payload_count, 	{ "SMT LLS Payload Count", 		"lls.smt.payload_count", 		FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		//per-smt payload entity
		{ &hf_lls_signedmultitable_lls_payload_id, 		{ "SMT LLS Payload ID", 		"lls.smt.payload_id", 			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_lls_signedmultitable_lls_payload_version, { "SMT LLS Payload Version",	"lls.smt.payload_version", 		FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_lls_signedmultitable_lls_payload_length, 	{ "SMT LLS Payload Length", 	"lls.smt.payload_length", 		FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_lls_signedmultitable_signature_length, 	{ "SMT Signature Length", 		"lls.smt.signature_length", 	FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_lls_signedmultitable_signature_bytes, 	{ "SMT Signature Bytes", 		"lls.smt.signature_bytes", 		FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_lls_signedmultitable_signature_valid, 	{ "SMT Signature CMS", 		"lls.smt.signature_valid", 		FT_STRING, STR_ASCII, NULL, 0x0, NULL, HFILL }},
		{ &hf_lls_signedmultitable_signature_invalid, 	{ "SMT Signature CMS", 		"lls.smt.signature_invalid", 	FT_STRING, STR_ASCII, NULL, 0x0, NULL, HFILL }}



    };

    /* Setup protocol subtree array */
    static gint *ett_ptr[] = {
        &ett_main,
		&ett_certificationdata,
		&ett_signedmultitable
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


#ifdef HAVE_OPENSSL

	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();

#endif
}

void proto_reg_handoff_atsc3_lls(void)
{
    dissector_handle_t handle;

    handle = create_dissector_handle(dissect_atsc3_lls, proto_atsc3_lls);

    //dissector_add_uint("ip.dst", ATSC3_LLS_IP_ADDRESS_UINT, handle);
    dissector_add_uint("udp.port", ATSC3_LLS_UDP_PORT, handle);


    //    dissector_add_for_decode_as_with_preference("udp.port", handle);
    xml_handle = find_dissector_add_dependency("xml", proto_atsc3_lls);
    proto_xml = dissector_handle_get_protocol_index(xml_handle);


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
