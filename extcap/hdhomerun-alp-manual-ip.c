/* hdhomerun-alp.c
 * hdhomerun-alp is an extcap tool used to get packets exported from a hdhomerun via http in ALP payload format
 *
 * Copyright 2022, jjustman <jjustman@ngbp.org>
 *
 * borrowed from udpdump.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <extcap/extcap-base.h>

#include <glib.h>
#include <glib/gprintf.h>
#include <stdlib.h>

#ifdef HAVE_SYS_TIME_H
	#include <sys/time.h>
#endif

#ifdef HAVE_NETINET_IN_H
	#include <netinet/in.h>
#endif

#include <string.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
	#include <unistd.h>
#endif

#ifdef HAVE_LIBCURL
	#include <curl/curl.h>
#endif

#include <libhdhomerun/hdhomerun.h>
#include <libhdhomerun/fixups_strnstr.h>
#include <libhdhomerun/jsmn.h>

#include <writecap/pcapio.h>
#include <wiretap/wtap.h>
#include <wsutil/strtoi.h>
#include <wsutil/inet_addr.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/socket.h>
#include <wsutil/please_report_bug.h>

#include <cli_main.h>

#define PCAP_SNAPLEN 0xffff

#define HDHOMERUN_MANUAL_EXTCAP_INTERFACE		"hdhomerun-alp-manual-ip"
#define HDHOMERUN_DEFAULT_IP_ADDRESS 			"192.168.3.2"
#define HDHOMERUN_DEFAULT_CHANNEL 				"ch34p0p1"

#define HDHOMERUN_ALP_EXTCAP_INTERFACE 			"hdhomerun_alp"
#define HDHOMERUN_ALP_EXTCAP_VERSION_MAJOR 		"0"
#define HDHOMERUN_ALP_EXTCAP_VERSION_MINOR		"1"
#define HDHOMERUN_ALP_EXTCAP_VERSION_RELEASE	"0"

#define PKT_BUF_SIZE 65535

#define HDHOMERUN_ALP_EXTCAP_EXPORT_HEADER_LEN 40

/* Tags (from exported_pdu.h) */
#define EXP_PDU_TAG_PROTO_NAME	12
#define EXP_PDU_TAG_IPV4_SRC	20
#define EXP_PDU_TAG_IPV4_DST	21
#define EXP_PDU_TAG_SRC_PORT	25
#define EXP_PDU_TAG_DST_PORT	26

static gboolean run_loop = TRUE;

enum {
	EXTCAP_BASE_OPTIONS_ENUM,
	OPT_HELP,
	OPT_VERSION,
	OPT_HDHOMERUN_IP_ADDRESS,
	OPT_HDHOMERUN_CHANNEL
};

static struct option longopts[] = {
	EXTCAP_BASE_OPTIONS,
	/* Generic application options */
	{ "help", no_argument, NULL, OPT_HELP},
	{ "version", no_argument, NULL, OPT_VERSION},
	/* Interfaces options */
	{ "hdhomerun_ip_address", required_argument, NULL, OPT_HDHOMERUN_IP_ADDRESS},
	{ "hdhomerun_channel", required_argument, NULL, OPT_HDHOMERUN_CHANNEL},

	{ 0, 0, 0, 0 }
};



typedef struct curl_callback_context_pcap {

	//for alp-pcap pipe i/o flush
	FILE* 		pcap_fp;
	guint 		invocation_count;

	//for in-memory (e.g. .json) object capture
	gboolean 	use_in_memory_payload;
	char* 		response;
	size_t		size;

	size_t 		total_bytes_received;

} curl_callback_context_pcap_t;

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  curl_callback_context_pcap_t* curl_callback_context_pcap = (curl_callback_context_pcap_t *)userp;

  curl_callback_context_pcap->total_bytes_received += realsize;

  if(!curl_callback_context_pcap->use_in_memory_payload) {

	  g_debug("::WriteMemoryCallback, realsize: %lu, pcap_fp: %p, run_loop: %d, callback invocation count: %d, total_bytes_received: %lu",
			  realsize, curl_callback_context_pcap->pcap_fp, run_loop, curl_callback_context_pcap->invocation_count++, curl_callback_context_pcap->total_bytes_received);
	  if(run_loop) {
		  if(curl_callback_context_pcap->pcap_fp) {
			  if(size) {
				  fwrite(contents, realsize, 1, curl_callback_context_pcap->pcap_fp);
				  fflush(curl_callback_context_pcap->pcap_fp);
			  }
			  return realsize;
		  } else {
			  g_error("mem->pcap_fd is NULL!");
		  }
	  } else {
		  g_info("exiting callback loop");
	  }
  } else {
	   char *ptr = realloc(curl_callback_context_pcap->response, curl_callback_context_pcap->size + realsize + 1);
	   if(ptr == NULL)
	     return 0;  /* out of memory! */

	   curl_callback_context_pcap->response = ptr;
	   memcpy(&(curl_callback_context_pcap->response[curl_callback_context_pcap->size]), contents, realsize);
	   curl_callback_context_pcap->size += realsize;
	   curl_callback_context_pcap->response[curl_callback_context_pcap->size] = 0;

	   return realsize;
  }

  return -1;

}
//hdhomerun sig handlers


static volatile sig_atomic_t sigabort_flag = false;
static volatile sig_atomic_t siginfo_flag = false;

static void sigabort_handler(int arg)
{
	sigabort_flag = true;
}

static void siginfo_handler(int arg)
{
	siginfo_flag = true;
}

static void register_signal_handlers(sig_t sigpipe_handler, sig_t sigint_handler, sig_t siginfo_handler)
{
#if defined(SIGPIPE)
	signal(SIGPIPE, sigpipe_handler);
#endif
#if defined(SIGINT)
	signal(SIGINT, sigint_handler);
#endif
#if defined(SIGINFO)
	signal(SIGINFO, siginfo_handler);
#endif
}


static int cmd_get(struct hdhomerun_device_t *hd, const char *item, char** ret_value)
{
	char *ret_error;
	if (hdhomerun_device_get_var(hd, item, ret_value, &ret_error) < 0) {
		g_error("communication error sending request to hdhomerun device\n");
		return -1;
	}

	if (ret_error) {
		g_error("%s\n", ret_error);
		return 0;
	}

	//printf("%s\n", ret_value);
	return 1;
}




static int cmd_set_internal(struct hdhomerun_device_t *hd, const char *item, const char *value)
{
	char *ret_error;
	if (hdhomerun_device_set_var(hd, item, value, NULL, &ret_error) < 0) {
		g_error("communication error sending request to hdhomerun device\n");
		return -1;
	}

	if (ret_error) {
		g_error("%s\n", ret_error);
		return 0;
	}

	return 1;
}


static int list_config_from_hdhomerun_full_channel_scan(char *interface)
{
	unsigned inc = 0;

	if (!interface) {
		g_warning("No interface specified.");
		return EXIT_FAILURE;
	}

	printf("arg {number=%u}{call=--hdhomerun_channel}{display=ATSC3 Channel to listen}"
		"{type=selector}{tooltip=Channel and PLPs to listen}\n",
		inc++);

	/*
	 *
	 * borrowed from hdhomerun_config.c
	 *
	 * default to "/tuner0"
	 */

	struct hdhomerun_device_t *hd;

	hd = hdhomerun_device_create_from_str(interface, NULL);
	if (!hd) {
		g_error("invalid device id: %s\n", interface);
		return -1;
	}

	const char* tuner_str= "/tuner0";

	if (hdhomerun_device_set_tuner_from_str(hd, tuner_str) <= 0) {
		g_error("invalid tuner number");
		return -1;
	}

	char *ret_error = NULL;
	if (hdhomerun_device_tuner_lockkey_request(hd, &ret_error) <= 0) {
		g_error("failed to lock tuner: %s", ret_error);
		return -1;
	}

	hdhomerun_device_set_tuner_target(hd, "none");

	char *channelmap;
	if (hdhomerun_device_get_tuner_channelmap(hd, &channelmap) <= 0) {
		g_error("failed to query channelmap from device\n");
		return -1;
	}

	const char *channelmap_scan_group = hdhomerun_channelmap_get_channelmap_scan_group(channelmap);
	if (!channelmap_scan_group) {
		g_error("unknown channelmap '%s'\n", channelmap);
		return -1;
	}

	if (hdhomerun_device_channelscan_init(hd, channelmap_scan_group) <= 0) {
		g_error("failed to initialize channel scan\n");
		return -1;
	}


	register_signal_handlers(sigabort_handler, sigabort_handler, siginfo_handler);

	int ret = 0;
	while (!sigabort_flag) {
		struct hdhomerun_channelscan_result_t result;
		ret = hdhomerun_device_channelscan_advance(hd, &result);
		if (ret <= 0) {
			break;
		}

//			g_debug(fp, "SCANNING: %u (%s)\n",
//				(unsigned int)result.frequency, result.channel_str
//			);

		ret = hdhomerun_device_channelscan_detect(hd, &result);
		if (ret < 0) {
			break;
		}
		if (ret == 0) {
			continue;
		}

		char* channel_num_string = strnstr(result.channel_str, ":", strlen(result.channel_str));

		if(channel_num_string) {
			channel_num_string++; //move past ';'

			if(strncmp(result.status.lock_str, "atsc3", 5) == 0) {
				char* my_plp_string = "";
				char* ret_value = NULL;

				cmd_get(hd, "/tuner0/plpinfo", &ret_value);
				if(ret_value) {
					//find our unique PLPs for tuning
					char* my_pos = ret_value;
					char* last_pos = ret_value;
					while(my_pos && strlen(my_pos)) {
						my_pos = strnstr(my_pos, ":", strlen(my_pos));
						if(my_pos) {
							//jjustman-2022-10-19 - transient memory leak here as we re-write my_plp_string
							my_plp_string = g_strdup_printf("%sp%.*s", my_plp_string, (my_pos - last_pos),  last_pos);
							last_pos = strnstr(my_pos, "\n", strlen(my_pos)) + 1;
							my_pos++;
						}
					}
				}

				printf("value {arg=%u}{value=ch%s%s}{display=ATSC3 RF Channel: %s (plps: %s)}\n",
					inc - 1, channel_num_string, my_plp_string, result.channel_str, my_plp_string);
			}
		}
	}


	hdhomerun_device_tuner_lockkey_release(hd);
	extcap_config_debug(&inc);

	return EXIT_SUCCESS;
}


static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}

//use GArray*
typedef struct atsc3_frequency_plps {
	int frequency_hz;
	char* plp_info_string;

	guint listen_plp[4]; //note 0xff means ignore
} atsc3_frequency_plps_t;


static int list_config(char *interface) {
	unsigned inc = 0;

	if (!interface) {
		g_warning("No interface specified.");
		return EXIT_FAILURE;
	}


	printf("arg {number=%u}{call=--hdhomerun_ip_address}{display=HDHomerun IP address to connect to}"
			"{type=string}{default=%s}{tooltip=Channel and PLPs to listen}\n",
			inc++, HDHOMERUN_DEFAULT_IP_ADDRESS);

	printf("arg {number=%u}{call=--hdhomerun_channel}{display=ATSC3 Channel to listen}"
			"{type=string}{default=c34p0}{tooltip=Channel and PLPs to listen}\n",
			inc++);

//	printf("value {arg=%u}{value=ch%d%s}{display=ATSC3 RF Channel: %d (plps: %s)}\n",
//			inc - 1, atsc3_frequency_plps->frequency_hz, my_plp_string,  atsc3_frequency_plps->frequency_hz, my_plp_string);

	extcap_config_debug(&inc);

	return EXIT_SUCCESS;
}

/*
 * lineup.json?tuning response payload looks like:
 *
 * [{"GuideNumber":"104.1","GuideName":"KOMO","Modulation":"atsc3","Frequency":533000000,"PLPConfig":"0","ProgramNumber":5002,"VideoCodec":"HEVC","ATSC3":1,"URL":"http://192.168.0.82:5004/auto/v104.1"},{"GuideNumber":"105.1","GuideName":"KING","Modulation":"atsc3","Frequency":575000000,"PLPConfig":"0","ProgramNumber":5002,"VideoCodec":"HEVC","ATSC3":1,"URL":"http://192.168.0.82:5004/auto/v105.1"},{"GuideNumber":"107.1","GuideName":"KIRO","Modulation":"atsc3","Frequency":533000000,"PLPConfig":"0","ProgramNumber":5003,"VideoCodec":"HEVC","ATSC3":1,"URL":"http://192.168.0.82:5004/auto/v107.1"},{"GuideNumber":"113.1","GuideName":"KCPQ","Modulation":"atsc3","Frequency":575000000,"PLPConfig":"0","ProgramNumber":5003,"VideoCodec":"HEVC","ATSC3":1,"URL":"http://192.168.0.82:5004/auto/v113.1"},{"GuideNumber":"116.1","GuideName":"KONG","Modulation":"atsc3","Frequency":575000000,"PLPConfig":"0","ProgramNumber":5001,"VideoCodec":"HEVC","ATSC3":1,"URL":"http://192.168.0.82:5004/auto/v116.1"},{"GuideNumber":"122.1","GuideName":"KZJO","Modulation":"atsc3","Frequency":575000000,"PLPConfig":"0","ProgramNumber":5004,"VideoCodec":"HEVC","ATSC3":1,"URL":"http://192.168.0.82:5004/auto/v122.1"},{"GuideNumber":"151.1","GuideName":"KUNS","Modulation":"atsc3","Frequency":533000000,"PLPConfig":"0","ProgramNumber":5005,"VideoCodec":"HEVC","ATSC3":1,"URL":"http://192.168.0.82:5004/auto/v151.1"}]
 */
static int list_config_from_hdhomerun_ip(char *interface)
{
	unsigned inc = 0;

	if (!interface) {
		g_warning("No interface specified.");
		return EXIT_FAILURE;
	}

	GArray* atsc3_frequency_plps_array = g_array_new(FALSE, FALSE, sizeof(atsc3_frequency_plps_t*));

	curl_callback_context_pcap_t* curl_callback_context_pcap = calloc(1, sizeof(curl_callback_context_pcap_t));
	curl_callback_context_pcap->use_in_memory_payload = TRUE;

	//setup our hdhomerun connection

	struct hdhomerun_device_t *hd;

	hd = hdhomerun_device_create_from_str(interface, NULL);
	if (!hd) {
		g_error("invalid device id: %s\n", interface);
		return -1;
	}

	const char* tuner_str= "/tuner0";

	if (hdhomerun_device_set_tuner_from_str(hd, tuner_str) <= 0) {
		g_error("invalid tuner number");
		return -1;
	}

	char *ret_error = NULL;
	if (hdhomerun_device_tuner_lockkey_request(hd, &ret_error) <= 0) {
		g_error("failed to lock tuner: %s", ret_error);
		return -1;
	}

	hdhomerun_device_set_tuner_target(hd, "none");

	char *channelmap;
	if (hdhomerun_device_get_tuner_channelmap(hd, &channelmap) <= 0) {
		g_error("failed to query channelmap from device\n");
		return -1;
	}

	const char *channelmap_scan_group = hdhomerun_channelmap_get_channelmap_scan_group(channelmap);
	if (!channelmap_scan_group) {
		g_error("unknown channelmap '%s'\n", channelmap);
		return -1;
	}


#ifdef HAVE_LIBCURL
	CURL* curl_http_handle = NULL;
	CURLcode res;

	char* hdhomerun_url = NULL;



	curl_global_init(CURL_GLOBAL_ALL);

	/* init the curl session */
	curl_http_handle = curl_easy_init();


	/* specify URL to get */

	/*
	 *
	 * https://forum.silicondust.com/forum/viewtopic.php?t=74254
	 *
	 */
	hdhomerun_url = g_strdup_printf("http://%s/lineup.json?tuning", interface);
	g_info("hdhomerun_url is: %s", hdhomerun_url);

	curl_easy_setopt(curl_http_handle, CURLOPT_URL, hdhomerun_url);

	/* send all data to this function  */
	curl_easy_setopt(curl_http_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

	/* we pass our 'chunk' struct to the callback function */
	curl_easy_setopt(curl_http_handle, CURLOPT_WRITEDATA, (void *)curl_callback_context_pcap);

	/* some servers do not like requests that are made without a user-agent
	 field, so we provide one */
	curl_easy_setopt(curl_http_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

	/* get it! */
	res = curl_easy_perform(curl_http_handle);

	/* check for errors */
	if(res != CURLE_OK) {

		g_error("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
	}	else {
	/*
	 * Now, our chunk.memory points to a memory block that is chunk.size
	 * bytes big and contains the remote file.
	 *
	 * Do something nice with it!
	 */

		g_info("total %lu bytes retrieved\n", curl_callback_context_pcap->total_bytes_received);
		g_info("http response is: %s", curl_callback_context_pcap->response);
	}

	/* cleanup curl stuff */
	curl_easy_cleanup(curl_http_handle);

	/* we are done with libcurl, so clean it up */
	curl_global_cleanup();

#else

	g_debug("No libcurl support!");

	return -1;
#endif

	if(curl_callback_context_pcap->response) {
		int r;

		jsmn_parser p;
		//rough guestimate...
		int num_tokens_to_alloc = strlen(curl_callback_context_pcap->response)/4;

		jsmntok_t* t = calloc(num_tokens_to_alloc, sizeof(jsmntok_t));

		jsmn_init(&p);
		r = jsmn_parse(&p, curl_callback_context_pcap->response, strlen(curl_callback_context_pcap->response), t, num_tokens_to_alloc);
		if (r < 0) {
			g_error("Failed to parse JSON: %d\n", r);
			return 1;
		}

		if (r < 1 || t[0].type != JSMN_ARRAY) {
			g_error("Array expected\n");
			return 1;
		}

		for (int i = 1; i < r; i++) {


			if(t[i].type == JSMN_OBJECT) {
				//see if we
				g_debug("Object start at token index: %d, type: %d, size: %d", i, t[i].type, t[i].size);
				jsmntok_t* modulation_value_atsc3 = NULL;
				jsmntok_t* frequency_value = NULL;

				for(int k=0; k <= t[i].size; k++) {
					if(t[i+k].type == JSMN_STRING) {
						jsmntok_t* key = &t[i + k];
						int key_len = (key->end - key->start);

						jsmntok_t* val = &t[i + k + 1];
						int val_len = (val->end - val->start);

						g_debug(" key: %.*s, val: %.*s", key_len, &curl_callback_context_pcap->response[key->start], val_len, &curl_callback_context_pcap->response[val->start]);
						if(jsoneq(curl_callback_context_pcap->response, key, "Modulation") == 0 && jsoneq(curl_callback_context_pcap->response, val, "atsc3") == 0) {
							modulation_value_atsc3 = val;
						} else if(jsoneq(curl_callback_context_pcap->response, key, "Frequency") == 0) {
							frequency_value = val;
						}

						k++;
						//ugh, such a gross hack!
						t[i].size++;
					}
				}

				if(modulation_value_atsc3 && frequency_value) {
					gboolean has_matching_frequency = FALSE;
					//chomp us down for atoi()...
					int frequency_value_len = (frequency_value->end - frequency_value->start);

					char* my_frequency_string = g_strdup_printf("%.*s", frequency_value_len, &curl_callback_context_pcap->response[frequency_value->start]);

					int my_frequency_hz = atoi(my_frequency_string);
					free(my_frequency_string);

					//see if we have a matching frequency
					for(guint l=0; l < atsc3_frequency_plps_array->len && !has_matching_frequency; l++) {
						atsc3_frequency_plps_t* atsc3_frequency_plps_to_check = g_array_index(atsc3_frequency_plps_array, atsc3_frequency_plps_t*, l);
						g_debug("checking my_frequency_hz: %d, against array idx: %d, ptr: %p, frequency_hz: %d", my_frequency_hz, l, atsc3_frequency_plps_to_check, atsc3_frequency_plps_to_check->frequency_hz);

						if(atsc3_frequency_plps_to_check->frequency_hz == my_frequency_hz) {
							has_matching_frequency = TRUE;
							break;
						}
					}

					if(!has_matching_frequency) {
						atsc3_frequency_plps_t* atsc3_frequency_plps = calloc(1, sizeof(atsc3_frequency_plps_t));
						atsc3_frequency_plps->frequency_hz = my_frequency_hz;
						//tune hdhomerun to this frequency and then call tuner0/plpinfo

						char* my_tune_command = g_strdup_printf("atsc3:%d", atsc3_frequency_plps->frequency_hz);

						g_debug("calling set /tuner0/channel with command: %s", my_tune_command);

						cmd_set_internal(hd, "/tuner0/channel", my_tune_command);

						//platform agnostic sleep from libhdhomerun
						msleep_approx(1000);

						g_debug("calling /tuner0/plpinfo");

						char* temp_plp_info_string = NULL;
						cmd_get(hd, "/tuner0/plpinfo", &temp_plp_info_string);
						atsc3_frequency_plps->plp_info_string = strdup(temp_plp_info_string);

						g_debug(" pushing atsc3_frequency_plps: %p, atsc3_frequency_plps->frequency_hz: %d, atsc3_frequency_plps->plp_info_string: %s",
								atsc3_frequency_plps, atsc3_frequency_plps->frequency_hz, atsc3_frequency_plps->plp_info_string);

						g_array_append_vals(atsc3_frequency_plps_array, &atsc3_frequency_plps, 1);
					}
				}
			}
		}

		free(t);
		t = NULL;

	}

	hdhomerun_device_tuner_lockkey_release(hd);

	if(curl_callback_context_pcap->response) {
		free(curl_callback_context_pcap->response);
		curl_callback_context_pcap->response = NULL;
	}

	if(curl_callback_context_pcap) {
		free(curl_callback_context_pcap);
		curl_callback_context_pcap = NULL;
	}


	printf("arg {number=%u}{call=--hdhomerun_channel}{display=ATSC3 Channel to listen}"
		"{type=selector}{tooltip=Channel and PLPs to listen}\n",
		inc++);

	for(guint i=0; i < atsc3_frequency_plps_array->len; i++) {
		char* my_plp_string = "";

		atsc3_frequency_plps_t* atsc3_frequency_plps = g_array_index(atsc3_frequency_plps_array, atsc3_frequency_plps_t*, i);

		char* my_pos = atsc3_frequency_plps->plp_info_string;
		char* last_pos = atsc3_frequency_plps->plp_info_string;
		while(my_pos && strlen(my_pos)) {
			my_pos = strnstr(my_pos, ":", strlen(my_pos));
			if(my_pos) {
				//jjustman-2022-10-19 - transient memory leak here as we re-write my_plp_string
				my_plp_string = g_strdup_printf("%sp%.*s", my_plp_string, (my_pos - last_pos),  last_pos);
				last_pos = strnstr(my_pos, "\n", strlen(my_pos)) + 1;
				my_pos++;
			}
		}

		printf("value {arg=%u}{value=ch%d%s}{display=ATSC3 RF Channel: %d (plps: %s)}\n",
				inc - 1, atsc3_frequency_plps->frequency_hz, my_plp_string,  atsc3_frequency_plps->frequency_hz, my_plp_string);


	}


	extcap_config_debug(&inc);

	return EXIT_SUCCESS;
}


//example run: /Users/jjustman/Desktop/2022-08-28-silicondust-wireshark/wireshark/build/run/Wireshark.app/Contents/MacOS/extcap/hdhomerun_alp --extcap-interfaces --extcap-version=3.3

static int discover_and_register_hdhomerun_interfaces(extcap_parameters* extcap_conf)
{
	uint32_t target_ip = 0;
//	if (target_ip_str) {
//		target_ip = parse_ip_addr(target_ip_str);
//		if (target_ip == 0) {
//			fprintf(stderr, "invalid ip address: %s\n", target_ip_str);
//			return -1;
//		}
//	}

	struct hdhomerun_discover_device_t result_list[64];
	int result_count = hdhomerun_discover_find_devices_custom_v2(target_ip, HDHOMERUN_DEVICE_TYPE_WILDCARD, HDHOMERUN_DEVICE_ID_WILDCARD, result_list, 64);
	if (result_count < 0) {
		fprintf(stderr, "error sending discover request\n");
		return -1;
	}

	struct hdhomerun_discover_device_t *result = result_list;
	struct hdhomerun_discover_device_t *result_end = result_list + result_count;

	int valid_count = 0;
	while (result < result_end) {
		if (result->device_id == 0) {
			result++;
			continue;
		}

//		printf("hdhomerun device %08X found at %u.%u.%u.%u\n",
//			(unsigned int)result->device_id,
//			(unsigned int)(result->ip_addr >> 24) & 0x0FF, (unsigned int)(result->ip_addr >> 16) & 0x0FF,
//			(unsigned int)(result->ip_addr >> 8) & 0x0FF, (unsigned int)(result->ip_addr >> 0) & 0x0FF
//		);
//

		char* extcap_interface_ipaddress = g_strdup_printf("%u.%u.%u.%u", (unsigned int)(result->ip_addr >> 24) & 0x0FF, (unsigned int)(result->ip_addr >> 16) & 0x0FF, (unsigned int)(result->ip_addr >> 8) & 0x0FF, (unsigned int)(result->ip_addr >> 0) & 0x0FF);
		//ip address of HDHomeRun device to connect to. Defaults to: %s", HDHOMERUN_DEFAULT_IP_ADDRESS);

		extcap_base_register_interface(extcap_conf, extcap_interface_ipaddress, "HDHomeRun ALP remote capture", 1, "ATSC3 ALP");

		g_free(extcap_interface_ipaddress);

		valid_count++;
		result++;
	}

	if (valid_count == 0) {
		exit(0);
	}

	return valid_count;
}

static void exit_from_loop(int signo _U_)
{
	g_warning("Exiting from main loop");
	run_loop = FALSE;
}

static int setup_dumpfile(const char* fifo, FILE** fp)
{
	guint64 bytes_written = 0;
	int err;

	if (!g_strcmp0(fifo, "-")) {
		*fp = stdout;
		return EXIT_SUCCESS;
	}

	*fp = fopen(fifo, "wb");
	if (!(*fp)) {
		g_warning("Error creating output file: %s", g_strerror(errno));
		return EXIT_FAILURE;
	}
//	libpcap_write_file_header()
//	if (!libpcap_write_file_header(*fp, 252, PCAP_SNAPLEN, FALSE, &bytes_written, &err)) {
//		g_warning("Can't write pcap file header: %s", g_strerror(err));
//		return EXIT_FAILURE;
//	}

	return EXIT_SUCCESS;
}
//
//static void add_proto_name(guint8* mbuf, guint* offset, const char* proto_name)
//{
//	size_t proto_str_len = strlen(proto_name);
//	guint16 proto_name_len = (guint16)((proto_str_len + 3) & 0xfffffffc);
//
//	mbuf[*offset] = 0;
//	mbuf[*offset+1] = EXP_PDU_TAG_PROTO_NAME;
//	*offset += 2;
//	mbuf[*offset] = proto_name_len >> 8;
//	mbuf[*offset+1] = proto_name_len & 0xff;
//	*offset += 2;
//
//	memcpy(mbuf + *offset, proto_name, proto_str_len);
//	*offset += proto_name_len;
//}
//
//static void add_ip_source_address(guint8* mbuf, guint* offset, uint32_t source_address)
//{
//	mbuf[*offset] = 0x00;
//	mbuf[*offset+1] = EXP_PDU_TAG_IPV4_SRC;
//	mbuf[*offset+2] = 0;
//	mbuf[*offset+3] = 4;
//	*offset += 4;
//	memcpy(mbuf + *offset, &source_address, 4);
//	*offset += 4;
//}
//
//static void add_ip_dest_address(guint8* mbuf, guint* offset, uint32_t dest_address)
//{
//	mbuf[*offset] = 0;
//	mbuf[*offset+1] = EXP_PDU_TAG_IPV4_DST;
//	mbuf[*offset+2] = 0;
//	mbuf[*offset+3] = 4;
//	*offset += 4;
//	memcpy(mbuf + *offset, &dest_address, 4);
//	*offset += 4;
//}
//
//static void add_udp_source_port(guint8* mbuf, guint* offset, uint16_t src_port)
//{
//	uint32_t port = htonl(src_port);
//
//	mbuf[*offset] = 0;
//	mbuf[*offset+1] = EXP_PDU_TAG_SRC_PORT;
//	mbuf[*offset+2] = 0;
//	mbuf[*offset+3] = 4;
//	*offset += 4;
//	memcpy(mbuf + *offset, &port, 4);
//	*offset += 4;
//}
//
//static void add_udp_dst_port(guint8* mbuf, guint* offset, uint16_t dst_port)
//{
//	uint32_t port = htonl(dst_port);
//
//	mbuf[*offset] = 0;
//	mbuf[*offset+1] = EXP_PDU_TAG_DST_PORT;
//	mbuf[*offset+2] = 0;
//	mbuf[*offset+3] = 4;
//	*offset += 4;
//	memcpy(mbuf + *offset, &port, 4);
//	*offset += 4;
//}
//
//static void add_end_options(guint8* mbuf, guint* offset)
//{
//	memset(mbuf + *offset, 0x0, 4);
//	*offset += 4;
//}

static int dump_packet(const char* proto_name, const guint16 listenport, const char* buf,
		const ssize_t buflen, const struct sockaddr_in clientaddr, FILE* fp)
{
	int ret = EXIT_SUCCESS;
//
//	guint8* mbuf;
//	guint offset = 0;
//	gint64 curtime = g_get_real_time();
//	guint64 bytes_written = 0;
//	int err;
//
//	/* The space we need is the standard header + variable lengths */
//	mbuf = (guint8*)g_malloc0(HDHOMERUN_ALP_EXTCAP_EXPORT_HEADER_LEN + ((strlen(proto_name) + 3) & 0xfffffffc) + buflen);
//
//	add_proto_name(mbuf, &offset, proto_name);
//	add_ip_source_address(mbuf, &offset, clientaddr.sin_addr.s_addr);
//	add_ip_dest_address(mbuf, &offset, WS_IN4_LOOPBACK);
//	add_udp_source_port(mbuf, &offset, clientaddr.sin_port);
//	add_udp_dst_port(mbuf, &offset, listenport);
//	add_end_options(mbuf, &offset);
//
//	memcpy(mbuf + offset, buf, buflen);
//	offset += (guint)buflen;
//
//	if (!libpcap_write_packet(fp,
//			(guint32)(curtime / G_USEC_PER_SEC), (guint32)(curtime % G_USEC_PER_SEC),
//			offset, offset, mbuf, &bytes_written, &err)) {
//		g_warning("Can't write packet: %s", g_strerror(err));
//		ret = EXIT_FAILURE;
//	}
//
//	fflush(fp);
//
//	g_free(mbuf);
	return ret;
}


static void run_listener(const char* fifo, const gchar* hdhomerun_ip_address, const gchar* hdhomerun_channel)
{
	struct sockaddr_in clientaddr;
	char* buf;
	ssize_t buflen;
	FILE* fp = NULL;

	if (signal(SIGINT, exit_from_loop) == SIG_ERR) {
		g_warning("Can't set signal handler");
		return;
	}

	if (setup_dumpfile(fifo, &fp) == EXIT_FAILURE) {
		if (fp)
			fclose(fp);
		return;
	}

#ifdef HAVE_LIBCURL
	CURLM* curl_multi_handle = NULL;
	CURL* curl_http_handle = NULL;
	CURLcode res;

	char* hdhomerun_url = NULL;

	curl_callback_context_pcap_t* curl_callback_context_pcap = calloc(1, sizeof(curl_callback_context_pcap_t));

	curl_callback_context_pcap->pcap_fp = fp;

	curl_global_init(CURL_GLOBAL_ALL);
	curl_multi_handle = curl_multi_init();


	/* init the curl session */
	curl_http_handle = curl_easy_init();

	//curl_multi_add_handle(curl_multi_handle, curl_http_handle);

	/* specify URL to get */

	/*
	 *
	 * https://forum.silicondust.com/forum/viewtopic.php?t=74254
	 *
	 */
	hdhomerun_url = g_strdup_printf("http://%s:5004/auto/%s?format=alp-pcap", hdhomerun_ip_address, hdhomerun_channel);
	g_info("hdhomerun_url is: %s", hdhomerun_url);


	//jjustman-2022-12-20 - set to infinite timeout as we won't get a payload response if there is no demod alp data when starting our extcap
	curl_easy_setopt(curl_http_handle, CURLOPT_TIMEOUT, 0);
	curl_easy_setopt(curl_http_handle, CURLOPT_CONNECTTIMEOUT, 0);

	g_info("setting CURLOPT_TIMEOUT to 0\n");

	curl_easy_setopt(curl_http_handle, CURLOPT_URL, hdhomerun_url);

	/* send all data to this function  */
	curl_easy_setopt(curl_http_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

	/* we pass our 'chunk' struct to the callback function */
	curl_easy_setopt(curl_http_handle, CURLOPT_WRITEDATA, (void *)curl_callback_context_pcap);

	/* some servers do not like requests that are made without a user-agent
	 field, so we provide one */
	curl_easy_setopt(curl_http_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

	/* get it! */
	res = curl_easy_perform(curl_http_handle);

	/* check for errors */
	if(res != CURLE_OK) {

		g_error("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
	}	else {
	/*
	 * Now, our chunk.memory points to a memory block that is chunk.size
	 * bytes big and contains the remote file.
	 *
	 * Do something nice with it!
	 */

		g_info("total %lu bytes retrieved\n", curl_callback_context_pcap->total_bytes_received);
	}

	/* cleanup curl stuff */
	curl_easy_cleanup(curl_http_handle);

//	free(chunk.memory);

	/* we are done with libcurl, so clean it up */

	curl_multi_cleanup(curl_multi_handle);


	curl_global_cleanup();

#else

	g_debug("Connection running to: %s, but no libcurl support!", hdhomerun_ip_address);
#endif


	fclose(fp);
}

int main(int argc, char *argv[])
{
	char* err_msg;
	int option_idx = 0;
	int result;
	guint16 port = 0;
	int ret = EXIT_FAILURE;
	extcap_parameters* extcap_conf = g_new0(extcap_parameters, 1);
	char* help_url;
	char* help_header = NULL;
	char* payload = NULL;
	char* ip_connection_msg = NULL;
	char* channel_connection_msg = NULL;

	gchar* hdhomerun_ip_address = NULL;
	gchar* hdhomerun_channel = NULL;

	/*
	 * Get credential information for later use.
	 */
	init_process_policies();

	/*
	 * Attempt to get the pathname of the directory containing the
	 * executable file.
	 */
	err_msg = init_progfile_dir(argv[0]);
	if (err_msg != NULL) {
		g_warning("Can't get pathname of directory containing the captype program: %s.",
			err_msg);
		g_free(err_msg);
	}

	help_url = data_file_url("hdhomerun_alp.html");
	extcap_base_set_util_info(extcap_conf, argv[0], HDHOMERUN_ALP_EXTCAP_VERSION_MAJOR, HDHOMERUN_ALP_EXTCAP_VERSION_MINOR, HDHOMERUN_ALP_EXTCAP_VERSION_RELEASE,
		help_url);
	g_free(help_url);

#ifdef HAVE_LIBCURL
	g_info("compiled with libcurl");

#else
	g_warning("Missing libcurl, no HDHomeRun connection will be available!");

#endif

	extcap_base_register_interface(extcap_conf, HDHOMERUN_MANUAL_EXTCAP_INTERFACE, "HDHomeRun ALP remote capture - manual IP", 1, "ATSC3 ALP");

	help_header = g_strdup_printf(
		" %s --extcap-interfaces\n"
		" %s --extcap-interface=%s --extcap-config\n"
		" %s --extcap-interface=%s --hdhomerun_ip_address %s --hdhomerun_channel %s --fifo myfifo --capture",
		argv[0],
		argv[0], HDHOMERUN_MANUAL_EXTCAP_INTERFACE,
		argv[0], HDHOMERUN_MANUAL_EXTCAP_INTERFACE, HDHOMERUN_DEFAULT_CHANNEL);

	extcap_help_add_header(extcap_conf, help_header);
	g_free(help_header);
	extcap_help_add_option(extcap_conf, "--help", "print this help");
	extcap_help_add_option(extcap_conf, "--version", "print the version");

	ip_connection_msg = g_strdup_printf("ip address of HDHomeRun device to connect to. Defaults to: %s", HDHOMERUN_DEFAULT_IP_ADDRESS);
	extcap_help_add_option(extcap_conf, "--hdhomerun_ip_address <address>", ip_connection_msg);
	g_free(ip_connection_msg);

	channel_connection_msg = g_strdup_printf("Channel and PLP's to listen to. Defaults to: %s", HDHOMERUN_DEFAULT_CHANNEL);
	extcap_help_add_option(extcap_conf, "--hdhomerun_channel <channel_and_plps>", channel_connection_msg);
	g_free(channel_connection_msg);

	opterr = 0;
	optind = 0;

	if (argc == 1) {
		extcap_help_print(extcap_conf);
		goto end;
	}

	while ((result = getopt_long(argc, argv, ":", longopts, &option_idx)) != -1) {
		switch (result) {

		case OPT_HELP:
			extcap_help_print(extcap_conf);
			ret = EXIT_SUCCESS;
			goto end;

		case OPT_VERSION:
			printf("%s\n", extcap_conf->version);
			goto end;

		case OPT_HDHOMERUN_IP_ADDRESS:
			hdhomerun_ip_address = g_strdup(optarg);
			break;

		case OPT_HDHOMERUN_CHANNEL:
			hdhomerun_channel = g_strdup(optarg);

		break;

//		case OPT_PAYLOAD:
//			g_free(payload);
//			payload = g_strdup(optarg);
//			break;

		case ':':
			/* missing option argument */
			g_warning("Option '%s' requires an argument", argv[optind - 1]);
			break;

		default:
			if (!extcap_base_parse_options(extcap_conf, result - EXTCAP_OPT_LIST_INTERFACES, optarg)) {
				g_warning("Invalid option: %s", argv[optind - 1]);
				goto end;
			}
		}
	}

	extcap_cmdline_debug(argv, argc);

	if (optind != argc) {
		g_warning("Unexpected extra option: %s", argv[optind]);
		goto end;
	}

	if (extcap_base_handle_interface(extcap_conf)) {
		ret = EXIT_SUCCESS;
		goto end;
	}

	if (extcap_conf->show_config) {
		ret = list_config(extcap_conf->interface);
		goto end;
	}

	//

//	if (!payload)
//		payload = g_strdup("data");
//
//	err_msg = ws_init_sockets();
//	if (err_msg != NULL) {
//		g_warning("Error: %s", err_msg);
//		g_free(err_msg);
//		g_warning("%s", please_report_bug());
//		goto end;
//	}

//	if (port == 0)
//		port = UDPDUMP_DEFAULT_PORT;

	if(!extcap_conf->interface) {
		g_error("missing hdhomerun interface address");
		goto end;
	}


	if(!hdhomerun_channel) {
		hdhomerun_channel = g_strdup(HDHOMERUN_DEFAULT_CHANNEL);
	}


	if (extcap_conf->capture)  {
		g_debug("extcap->interface: %s", extcap_conf->interface);

		hdhomerun_ip_address = g_strdup(extcap_conf->interface);

		run_listener(extcap_conf->fifo, hdhomerun_ip_address, hdhomerun_channel);
		g_free(hdhomerun_ip_address);
	}
end:
	/* clean up stuff */
	extcap_base_cleanup(&extcap_conf);
	g_free(payload);
	return ret;
}

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
