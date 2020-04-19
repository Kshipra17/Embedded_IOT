/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/* coap -- simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 *
 * Copyright (C) 2010--2020 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#ifdef _WIN32
#define strcasecmp _stricmp
#include "getopt.c"
#if !defined(S_ISDIR)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif
#ifndef R_OK
#define R_OK 4
#endif
static char* strndup(const char* s1, size_t n)
{
	char* copy = (char*)malloc(n + 1);
	if (copy) {
		memcpy(copy, s1, n);
		copy[n] = 0;
	}
	return copy;
};
#else
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#endif

/* Need to refresh time once per sec */

#include <coap2/coap.h>

/* temporary storage for dynamic resource representations */
static int quit = 0;

struct coap_resource_t *time_resource = NULL;

static int resource_flags = COAP_RESOURCE_FLAGS_NOTIFY_CON;

static const char *hint = "CoAP";
static int support_dynamic = 0;

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

/* SIGINT handler: set quit to 1 for graceful termination */
static void
handle_sigint(int signum UNUSED_PARAM) {
	quit = 1;
}

#define INDEX "This is a test server made with libcoap (see https://libcoap.net)\n" \
		"Copyright (C) 2010--2020 Olaf Bergmann <bergmann@tzi.org> and others\n\n"

static void
hnd_get_index(coap_context_t *ctx UNUSED_PARAM,
		struct coap_resource_t *resource,
		coap_session_t *session,
		coap_pdu_t *request,
		coap_binary_t *token,
		coap_string_t *query UNUSED_PARAM,
		coap_pdu_t *response) {

	coap_add_data_blocked_response(resource, session, request, response, token,
			COAP_MEDIATYPE_TEXT_PLAIN, 0x2ffff,
			strlen(INDEX),
			(const uint8_t *)INDEX);
}

static void
hnd_get_time(coap_context_t  *ctx UNUSED_PARAM,
		struct coap_resource_t *resource,
		coap_session_t *session,
		coap_pdu_t *request,
		coap_binary_t *token,
		coap_string_t *query,
		coap_pdu_t *response) {
	int dataBuf = 0;
	getTemperaturefromI2C(&dataBuf);
	char temp[] = itoa(dataBuf);
	coap_add_data_blocked_response(resource, session, request, response, token,
			COAP_MEDIATYPE_TEXT_PLAIN, 1,
			strlen(temp),
			dataBuf);
}
}

static void
hnd_put_time(coap_context_t *ctx UNUSED_PARAM,
		struct coap_resource_t *resource,
		coap_session_t *session UNUSED_PARAM,
		coap_pdu_t *request,
		coap_binary_t *token UNUSED_PARAM,
		coap_string_t *query UNUSED_PARAM,
		coap_pdu_t *response) {
	coap_tick_t t;
	size_t size;
	unsigned char *data;

	/* FIXME: re-set my_clock_base to clock_offset if my_clock_base == 0
	 * and request is empty. When not empty, set to value in request payload
	 * (insist on query ?ticks). Return Created or Ok.
	 */

	/* if my_clock_base was deleted, we pretend to have no such resource */

	/* coap_get_data() sets size to 0 on error */
	// (void)coap_get_data(request, &size, &data);

	//  if (size == 0)        /* re-init */
	//    my_clock_base = clock_offset;
	//  else {
	//    my_clock_base = 0;
	//    coap_ticks(&t);
	//    while(size--)
	//      my_clock_base = my_clock_base * 10 + *data++;
	//    my_clock_base -= t / COAP_TICKS_PER_SECOND;

	/* Sanity check input value */
	//    if (!gmtime(&my_clock_base)) {
	//      unsigned char buf[3];
	//      response->code = COAP_RESPONSE_CODE(400);
	//      coap_add_option(response,
	//                      COAP_OPTION_CONTENT_FORMAT,
	//                      coap_encode_var_safe(buf, sizeof(buf),
	//                      COAP_MEDIATYPE_TEXT_PLAIN), buf);
	//      coap_add_data(response, 22, (const uint8_t*)"Invalid set time value");
	//      /* re-init as value is bad */
	//      my_clock_base = clock_offset;
}





//typedef struct dynamic_resource_t {
//	coap_string_t *uri_path;
//	coap_string_t *value;
//	coap_resource_t *resource;
//	int created;
//	uint16_t media_type;
//} dynamic_resource_t;
//
//static int dynamic_count = 0;
//static dynamic_resource_t *dynamic_entry = NULL;
//
///*
// * Regular DELETE handler - used by resources created by the
// * Unknown Resource PUT handler
// */
//
//
///*
// * Regular GET handler - used by resources created by the
// * Unknown Resource PUT handler
// */
//
//static void
//hnd_get(coap_context_t *ctx UNUSED_PARAM,
//		coap_resource_t *resource,
//		coap_session_t *session,
//		coap_pdu_t *request,
//		coap_binary_t *token,
//		coap_string_t *query UNUSED_PARAM,
//		coap_pdu_t *response
//) {
//	coap_str_const_t *uri_path;
//	int i;
//	dynamic_resource_t *resource_entry = NULL;
//	coap_str_const_t value = { 0, NULL };
//	/*
//	 * request will be NULL if an Observe triggered request, so the uri_path,
//	 * if needed, must be abstracted from the resource.
//	 * The uri_path string is a const pointer
//	 */
//
//	uri_path = coap_resource_get_uri_path(resource);
//	if (!uri_path) {
//		response->code = COAP_RESPONSE_CODE(404);
//		return;
//	}
//
//	//  for (i = 0; i < dynamic_count; i++) {
//	//    if (coap_string_equal(uri_path, dynamic_entry[i].uri_path)) {
//	//      break;
//	//    }
//	//  }
//	//  if (i == dynamic_count) {
//	//    response->code = COAP_RESPONSE_CODE(404);
//	////    return;
//	//  }
//
//	resource_entry = &dynamic_entry[i];
//
//	if (resource_entry->value) {
//		value.length = resource_entry->value->length;
//		value.s = resource_entry->value->s;
//	}
//	coap_add_data_blocked_response(resource, session, request, response, token,
//			resource_entry->media_type, -1,
//			value.length,
//			value.s);
//	return;
//}
//
///*
// * Regular PUT handler - used by resources created by the
// * Unknown Resource PUT handler
// */
//
//static void
//hnd_put(coap_context_t *ctx UNUSED_PARAM,
//		coap_resource_t *resource,
//		coap_session_t *session UNUSED_PARAM,
//		coap_pdu_t *request,
//		coap_binary_t *token UNUSED_PARAM,
//		coap_string_t *query UNUSED_PARAM,
//		coap_pdu_t *response
//) {
//	coap_string_t *uri_path;
//	int i;
//	size_t size;
//	uint8_t *data;
//	coap_block_t block1;
//	dynamic_resource_t *resource_entry = NULL;
//	unsigned char buf[6];      /* space to hold encoded/decoded uints */
//	coap_opt_iterator_t opt_iter;
//	coap_opt_t *option;
//
//	/* get the uri_path */
//	uri_path = coap_get_uri_path(request);
//	if (!uri_path) {
//		response->code = COAP_RESPONSE_CODE(404);
//		return;
//	}
//
//	/*
//	 * Locate the correct dynamic block for this request
//	 */
//	for (i = 0; i < dynamic_count; i++) {
//		if (coap_string_equal(uri_path, dynamic_entry[i].uri_path)) {
//			break;
//		}
//	}
//	if (i == dynamic_count) {
//		if (dynamic_count >= support_dynamic) {
//			/* Should have been caught in hnd_unknown_put() */
//			response->code = COAP_RESPONSE_CODE(406);
//			coap_delete_string(uri_path);
//			return;
//		}
//		dynamic_count++;
//		dynamic_entry = realloc (dynamic_entry, dynamic_count * sizeof(dynamic_entry[0]));
//		if (dynamic_entry) {
//			dynamic_entry[i].uri_path = uri_path;
//			dynamic_entry[i].value = NULL;
//			dynamic_entry[i].resource = resource;
//			dynamic_entry[i].created = 1;
//			response->code = COAP_RESPONSE_CODE(201);
//			if ((option = coap_check_option(request, COAP_OPTION_CONTENT_TYPE, &opt_iter)) != NULL) {
//				dynamic_entry[i].media_type =
//						coap_decode_var_bytes (coap_opt_value (option), coap_opt_length (option));
//			}
//			else {
//				dynamic_entry[i].media_type = COAP_MEDIATYPE_TEXT_PLAIN;
//			}
//			/* Store media type of new resource in ct. We can use buf here
//			 * as coap_add_attr() will copy the passed string. */
//			memset(buf, 0, sizeof(buf));
//			snprintf((char *)buf, sizeof(buf), "%d", dynamic_entry[i].media_type);
//			/* ensure that buf is always zero-terminated */
//			assert(buf[sizeof(buf) - 1] == '\0');
//			buf[sizeof(buf) - 1] = '\0';
//			coap_add_attr(resource,
//					coap_make_str_const("ct"),
//					coap_make_str_const((char*)buf),
//					0);
//		} else {
//			dynamic_count--;
//			response->code = COAP_RESPONSE_CODE(500);
//			return;
//		}
//	} else {
//		/* Need to do this as coap_get_uri_path() created it */
//		coap_delete_string(uri_path);
//		response->code = COAP_RESPONSE_CODE(204);
//		dynamic_entry[i].created = 0;
//		coap_resource_notify_observers(dynamic_entry[i].resource, NULL);
//	}
//
//	resource_entry = &dynamic_entry[i];
//
//	if (coap_get_block(request, COAP_OPTION_BLOCK1, &block1)) {
//		/* handle BLOCK1 */
//		if (coap_get_data(request, &size, &data) && (size > 0)) {
//			size_t offset = block1.num << (block1.szx + 4);
//			coap_string_t *value = resource_entry->value;
//			if (offset == 0) {
//				if (value) {
//					coap_delete_string(value);
//					value = NULL;
//				}
//			}
//			else if (offset >
//			(resource_entry->value ? resource_entry->value->length : 0)) {
//				/* Upload is not sequential - block missing */
//				response->code = COAP_RESPONSE_CODE(408);
//				return;
//			}
//			else if (offset <
//					(resource_entry->value ? resource_entry->value->length : 0)) {
//				/* Upload is not sequential - block duplicated */
//				goto just_respond;
//			}
//			/* Add in new block to end of current data */
//			resource_entry->value = coap_new_string(offset + size);
//			memcpy (&resource_entry->value->s[offset], data, size);
//			resource_entry->value->length = offset + size;
//			if (value) {
//				memcpy (resource_entry->value->s, value->s, value->length);
//				coap_delete_string(value);
//			}
//		}
//		just_respond:
//		if (block1.m) {
//			response->code = COAP_RESPONSE_CODE(231);
//		}
//		else if (resource_entry->created) {
//			response->code = COAP_RESPONSE_CODE(201);
//		}
//		else {
//			response->code = COAP_RESPONSE_CODE(204);
//		}
//		coap_add_option(response,
//				COAP_OPTION_BLOCK1,
//				coap_encode_var_safe(buf, sizeof(buf),
//						((block1.num << 4) |
//								(block1.m << 3) |
//								block1.szx)),
//								buf);
//	}
//	else if (coap_get_data(request, &size, &data) && (size > 0)) {
//		/* Not a BLOCK1 with data */
//		if (resource_entry->value) {
//			coap_delete_string(resource_entry->value);
//			resource_entry->value = NULL;
//		}
//		resource_entry->value = coap_new_string(size);
//		memcpy (resource_entry->value->s, data, size);
//		resource_entry->value->length = size;
//	}
//	else {
//		/* Not a BLOCK1 and no data */
//		if (resource_entry->value) {
//			coap_delete_string(resource_entry->value);
//			resource_entry->value = NULL;
//		}
//	}
//}
//
///*
// * Unknown Resource PUT handler
// */



static void
init_resources(coap_context_t *ctx) {
	coap_resource_t *r;

	r = coap_resource_init(NULL, 0);
	coap_register_handler(r, COAP_REQUEST_GET, hnd_get_index);

	coap_add_resource(ctx, r);

	r = coap_resource_init(coap_make_str_const("temp"), resource_flags);
//	coap_register_handler(r, COAP_REQUEST_GET, hnd_get_time);
	coap_register_handler(r, COAP_REQUEST_PUT, hnd_put_time);


	coap_add_resource(ctx, r);
//	time_resource = r;
	//
	//  if (support_dynamic > 0) {
	//    /* Create a resource to handle PUTs to unknown URIs */
	//    r = coap_resource_unknown_init(hnd_unknown_put);
	//    coap_add_resource(ctx, r);
	//  }
	//#ifndef WITHOUT_ASYNC
	//  r = coap_resource_init(coap_make_str_const("async"), 0);
	//  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_async);
	//
	//  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
	//  coap_add_resource(ctx, r);
	//#endif /* WITHOUT_ASYNC */
}


int
main(int argc, char **argv) {
	coap_context_t  *ctx;
	char *group = NULL;
	char addr_str[2] = "::";
	char port_str[2] = "5683";
	int opt;
	coap_log_t log_level = LOG_WARNING;
	unsigned wait_ms;
	time_t t_last = 0;
	int coap_fd;
	fd_set m_readfds;
	int nfds = 0;
	size_t i;
#ifndef _WIN32
	struct sigaction sa;
#endif

	//  while ((opt = getopt(argc, argv, "A:d:c:C:g:h:i:k:l:mnNp:R:s:S:v:")) != -1) {
	//    switch (opt) {
	//    case 'A' :
	//      strncpy(addr_str, optarg, NI_MAXHOST-1);
	//      addr_str[NI_MAXHOST - 1] = '\0';
	//      break;
	//    case 'c' :
	//      cert_file = optarg;
	//      break;
	//    case 'C' :
	//      ca_file = optarg;
	//      break;
	//    case 'd' :
	//      support_dynamic = atoi(optarg);
	//      break;
	//    case 'g' :
	//      group = optarg;
	//      break;
	//    case 'h' :
	//      if (!optarg[0]) {
	//        hint = NULL;
	//        break;
	//      }
	//      hint = optarg;
	//      break;
	//    case 'i':
	//      if (!cmdline_read_identity_check(optarg)) {
	//        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
	//        exit(1);
	//      }
	//      break;
	//    case 'k' :
	//      key_length = cmdline_read_key(optarg, key, MAX_KEY);
	//      if (key_length < 0) {
	//        coap_log( LOG_CRIT, "Invalid Pre-Shared Key specified\n" );
	//        break;
	//      }
	//      key_defined = 1;
	//      break;
	//    case 'l':
	//      if (!coap_debug_set_packet_loss(optarg)) {
	//        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
	//        exit(1);
	//      }
	//      break;
	//    case 'm':
	//      use_pem_buf = 1;
	//      break;
	//    case 'n':
	//      require_peer_cert = 0;
	//      break;
	//    case 'N':
	//      resource_flags = COAP_RESOURCE_FLAGS_NOTIFY_NON;
	//      break;
	//    case 'p' :
	//      strncpy(port_str, optarg, NI_MAXSERV-1);
	//      port_str[NI_MAXSERV - 1] = '\0';
	//      break;
	//    case 'R' :
	//      root_ca_file = optarg;
	//      break;
	//    case 's':
	//      if (!cmdline_read_psk_sni_check(optarg)) {
	//        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
	//        exit(1);
	//      }
	//      break;
	//    case 'S':
	//      if (!cmdline_read_pki_sni_check(optarg)) {
	//        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
	//        exit(1);
	//      }
	//      break;
	//    case 'v' :
	//      log_level = strtol(optarg, NULL, 10);
	//      break;
	//    default:
	//      usage( argv[0], LIBCOAP_PACKAGE_VERSION );
	//      exit( 1 );
	//    }
	//  }
	//
	coap_startup();
	coap_set_log_level(log_level);

	ctx = get_context(addr_str, port_str);
	if (!ctx)
		return -1;

	init_resources(ctx);

	/* join multicast group if requested at command line */
//	if (group)
//		coap_join_mcast_group(ctx, group);
//
//	coap_fd = coap_context_get_coap_fd(ctx);
//	if (coap_fd != -1) {
//		/* if coap_fd is -1, then epoll is not supported within libcoap */
//		FD_ZERO(&m_readfds);
//		FD_SET(coap_fd, &m_readfds);
//		nfds = coap_fd + 1;
	//}

//#ifdef _WIN32
//	signal(SIGINT, handle_sigint);
//#else
//	memset (&sa, 0, sizeof(sa));
//	sigemptyset(&sa.sa_mask);
//	sa.sa_handler = handle_sigint;
//	sa.sa_flags = 0;
//	sigaction (SIGINT, &sa, NULL);
//	sigaction (SIGTERM, &sa, NULL);
//	/* So we do not exit on a SIGPIPE */
//	sa.sa_handler = SIG_IGN;
//	sigaction (SIGPIPE, &sa, NULL);
//#endif
//
//	wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
//
//	while ( !quit ) {
//		int result;
//
//		if (coap_fd != -1) {
//			fd_set readfds = m_readfds;
//			struct timeval tv;
//
//			tv.tv_sec = wait_ms / 1000;
//			tv.tv_usec = (wait_ms % 1000) * 1000;
//			/* Wait until any i/o takes place */
//			result = select (nfds, &readfds, NULL, NULL, &tv);
//			if (result == -1) {
//				if (errno != EAGAIN) {
//					coap_log(LOG_DEBUG, "select: %s (%d)\n", coap_socket_strerror(), errno);
//					break;
//				}
//			}
//			if (result > 0) {
//				if (FD_ISSET(coap_fd, &readfds)) {
//					result = coap_io_process(ctx, COAP_RUN_NONBLOCK);
//				}
//			}
//		}
//		else {
//			/* epoll is not supported within libcoap */
//			result = coap_io_process(ctx, wait_ms);
//		}
//		if ( result < 0 ) {
//			break;
//		} else if ( result && (unsigned)result < wait_ms ) {
//			/* decrement if there is a result wait time returned */
//			wait_ms -= result;
//		} else {
//			/*
//			 * result == 0, or result >= wait_ms
//			 * (wait_ms could have decremented to a small value, below
//			 * the granularity of the timer in coap_io_process() and hence
//			 * result == 0)
//			 */
//			//      time_t t_now = time(NULL);
//			//      if (t_last != t_now) {
//			//        /* Happens once per second */
//			//        t_last = t_now;
//			//        if (time_resource) {
//			//          coap_resource_notify_observers(time_resource, NULL);
//			//        }
//			//      }
//			//      if (result) {
//			//        /* result must have been >= wait_ms, so reset wait_ms */
//			//        wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
//			//      }
//		}
//		//
//		//#ifndef WITHOUT_ASYNC
//		//    /* check if we have to send asynchronous responses */
//		//    coap_ticks( &now );
//		//    check_async(ctx, now);
//		//#endif /* WITHOUT_ASYNC */
//		//  }

		coap_free_context(ctx);
		coap_cleanup();

		return 0;
	}


