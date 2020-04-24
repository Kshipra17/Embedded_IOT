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
#include <coap2/coap.h>
#include "I2C.h"

/* temporary storage for dynamic resource representations */
static int quit = 0;

struct coap_resource_t *time_resource = NULL;

static int resource_flags = COAP_RESOURCE_FLAGS_NOTIFY_CON;

static const char *hint = "CoAP";
static int support_dynamic = 0;

#ifndef WITHOUT_ASYNC
/* This variable is used to mimic long-running tasks that require
 * asynchronous responses. */
static coap_async_state_t *async = NULL;

/* A typedef for transfering a value in a void pointer */
typedef union {
	unsigned int val;
	void *ptr;
} async_data_t;
#endif /* WITHOUT_ASYNC */

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
hnd_get_temperature(coap_context_t  *ctx UNUSED_PARAM,
		struct coap_resource_t *resource,
		coap_session_t *session,
		coap_pdu_t *request,
		coap_binary_t *token,
		coap_string_t *query,
		coap_pdu_t *response) {

	unsigned char buf[15] = "";
	(void)request;
	float dataBuf = 0;
	short len = 0;
	getTemperaturefromI2C(&dataBuf);
	memset(buf,0,sizeof(buf));
	len = snprintf(buf,sizeof(buf),"%.2f",dataBuf);
	coap_add_data_blocked_response(resource, session, request, response, token, COAP_MEDIATYPE_TEXT_PLAIN, 3, len, buf);
}

#ifndef WITHOUT_ASYNC
static void
hnd_get_async(coap_context_t *ctx,
		struct coap_resource_t *resource UNUSED_PARAM,
		coap_session_t *session,
		coap_pdu_t *request,
		coap_binary_t *token UNUSED_PARAM,
		coap_string_t *query UNUSED_PARAM,
		coap_pdu_t *response) {
	unsigned long delay = 5;
	size_t size;

	if (async) {
		if (async->id != request->tid) {
			coap_opt_filter_t f;
			coap_option_filter_clear(f);
			response->code = COAP_RESPONSE_CODE(503);
		}
		return;
	}

	if (query) {
		const uint8_t *p = query->s;

		delay = 0;
		for (size = query->length; size; --size, ++p)
			delay = delay * 10 + (*p - '0');
	}

	async_data_t data;
	data.val = COAP_TICKS_PER_SECOND * delay;
	async = coap_register_async(ctx,
			session,
			request,
			COAP_ASYNC_SEPARATE | COAP_ASYNC_CONFIRM,
			data.ptr);
}

static void
check_async(coap_context_t *ctx,
		coap_tick_t now) {
	coap_pdu_t *response;
	coap_async_state_t *tmp;

	size_t size = 13;

	if (!async || now < async->created + (unsigned long)async->appdata)
		return;

	response = coap_pdu_init(async->flags & COAP_ASYNC_CONFIRM
			? COAP_MESSAGE_CON
					: COAP_MESSAGE_NON,
					  COAP_RESPONSE_CODE(205), 0, size);
	if (!response) {
		coap_log(LOG_DEBUG, "check_async: insufficient memory, we'll try later\n");
		async_data_t data = { .ptr = async->appdata };
		data.val = data.val + 15 * COAP_TICKS_PER_SECOND;
		async->appdata = data.ptr;
		return;
	}

	response->tid = coap_new_message_id(async->session);

	if (async->tokenlen)
		coap_add_token(response, async->tokenlen, async->token);

	coap_add_data(response, 4, (const uint8_t *)"done");

	if (coap_send(async->session, response) == COAP_INVALID_TID) {
		coap_log(LOG_DEBUG, "check_async: cannot send response for message\n");
	}
	coap_remove_async(ctx, async->session, async->id, &tmp);
	coap_free_async(async);
	async = NULL;
}
#endif /* WITHOUT_ASYNC */

typedef struct dynamic_resource_t {
	coap_string_t *uri_path;
	coap_string_t *value;
	coap_resource_t *resource;
	int created;
	uint16_t media_type;
} dynamic_resource_t;

static int dynamic_count = 0;
static dynamic_resource_t *dynamic_entry = NULL;

/*
 * Regular GET handler - used by resources created by the
 * Unknown Resource PUT handler
 */

static void
hnd_get(coap_context_t *ctx UNUSED_PARAM,
		coap_resource_t *resource,
		coap_session_t *session,
		coap_pdu_t *request,
		coap_binary_t *token,
		coap_string_t *query UNUSED_PARAM,
		coap_pdu_t *response
) {
	coap_str_const_t *uri_path;
	int i;
	dynamic_resource_t *resource_entry = NULL;
	coap_str_const_t value = { 0, NULL };
	/*
	 * request will be NULL if an Observe triggered request, so the uri_path,
	 * if needed, must be abstracted from the resource.
	 * The uri_path string is a const pointer
	 */

	uri_path = coap_resource_get_uri_path(resource);
	if (!uri_path) {
		response->code = COAP_RESPONSE_CODE(404);
		return;
	}

	for (i = 0; i < dynamic_count; i++) {
		if (coap_string_equal(uri_path, dynamic_entry[i].uri_path)) {
			break;
		}
	}
	if (i == dynamic_count) {
		response->code = COAP_RESPONSE_CODE(404);
		return;
	}

	resource_entry = &dynamic_entry[i];

	if (resource_entry->value) {
		value.length = resource_entry->value->length;
		value.s = resource_entry->value->s;
	}
	coap_add_data_blocked_response(resource, session, request, response, token,
			resource_entry->media_type, -1,
			value.length,
			value.s);
	return;
}


/*
 * Unknown Resource PUT handler
 */
static void
hnd_unknown_put(coap_context_t *ctx,
		coap_resource_t *resource UNUSED_PARAM,
		coap_session_t *session,
		coap_pdu_t *request,
		coap_binary_t *token,
		coap_string_t *query,
		coap_pdu_t *response
) {
	coap_resource_t *r;
	coap_string_t *uri_path;

	/* get the uri_path - will will get used by coap_resource_init() */
	uri_path = coap_get_uri_path(request);
	if (!uri_path) {
		response->code = COAP_RESPONSE_CODE(404);
		return;
	}

	if (dynamic_count >= support_dynamic) {
		response->code = COAP_RESPONSE_CODE(406);
		return;
	}

	/*
	 * Create a resource to handle the new URI
	 * uri_path will get deleted when the resource is removed
	 */
	r = coap_resource_init((coap_str_const_t*)uri_path,
			COAP_RESOURCE_FLAGS_RELEASE_URI | resource_flags);
	coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Dynamic\""), 0);

	/* We possibly want to Observe the GETs */
	coap_resource_set_get_observable(r, 1);
	coap_register_handler(r, COAP_REQUEST_GET, hnd_get);
	coap_add_resource(ctx, r);

	/* Do the PUT for this first call */
	//hnd_put(ctx, r, session, request, token, query, response);

	return;
}

static void
init_resources(coap_context_t *ctx) {
	coap_resource_t *r;

	r = coap_resource_init(NULL, 0);
	coap_register_handler(r, COAP_REQUEST_GET, hnd_get_index);

	coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
	coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"General Info\""), 0);
	coap_add_resource(ctx, r);

	r = coap_resource_init(coap_make_str_const("temperature"), resource_flags);
	coap_register_handler(r, COAP_REQUEST_GET, hnd_get_temperature);
	coap_resource_set_get_observable(r, 1);
	coap_add_resource(ctx, r);
	time_resource = r;

	if (support_dynamic > 0) {
		/* Create a resource to handle PUTs to unknown URIs */
		r = coap_resource_unknown_init(hnd_unknown_put);
		coap_add_resource(ctx, r);
	}
#ifndef WITHOUT_ASYNC
	r = coap_resource_init(coap_make_str_const("async"), 0);
	coap_register_handler(r, COAP_REQUEST_GET, hnd_get_async);

	coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
	coap_add_resource(ctx, r);
#endif /* WITHOUT_ASYNC */
}


static coap_context_t *
get_context(const char *node, const char *port) {
	coap_context_t *ctx = NULL;
	int s;
	struct addrinfo hints;
	struct addrinfo *result, *rp;

	ctx = coap_new_context(NULL);
	if (!ctx) {
		return NULL;
	}
	/* Need PSK set up before we set up (D)TLS endpoints */

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
	hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

	s = getaddrinfo(node, port, &hints, &result);
	if ( s != 0 ) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		coap_free_context(ctx);
		return NULL;
	}

	/* iterate through results until success */
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		coap_address_t addr, addrs;
		coap_endpoint_t *ep_udp = NULL, *ep_dtls = NULL;

		if (rp->ai_addrlen <= sizeof(addr.addr)) {
			coap_address_init(&addr);
			addr.size = rp->ai_addrlen;
			memcpy(&addr.addr, rp->ai_addr, rp->ai_addrlen);
			addrs = addr;
			if (addr.addr.sa.sa_family == AF_INET) {
				uint16_t temp = ntohs(addr.addr.sin.sin_port) + 1;
				addrs.addr.sin.sin_port = htons(temp);
			} else if (addr.addr.sa.sa_family == AF_INET6) {
				uint16_t temp = ntohs(addr.addr.sin6.sin6_port) + 1;
				addrs.addr.sin6.sin6_port = htons(temp);
			} else {
				goto finish;
			}

			ep_udp = coap_new_endpoint(ctx, &addr, COAP_PROTO_UDP);
			if (!ep_udp) {
				coap_log(LOG_CRIT, "cannot create UDP endpoint\n");
				continue;
			}
			if (ep_udp)
				goto finish;
		}
	}

	fprintf(stderr, "no context available for interface '%s'\n", node);
	coap_free_context(ctx);
	ctx = NULL;

	finish:
	freeaddrinfo(result);
	return ctx;
}

int
main(int argc, char **argv) {
	coap_context_t  *ctx;
	char *group = NULL;
	coap_tick_t now;
	char addr_str[NI_MAXHOST] = "::";
	char port_str[NI_MAXSERV] = "5683";
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
	coap_startup();
	coap_set_log_level(log_level);
	ctx = get_context(addr_str, port_str);

	if (!ctx)
		return -1;

	init_resources(ctx);

	/* join multicast group if requested at command line */
	if (group)
		coap_join_mcast_group(ctx, group);

	coap_fd = coap_context_get_coap_fd(ctx);
	if (coap_fd != -1) {
		/* if coap_fd is -1, then epoll is not supported within libcoap */
		FD_ZERO(&m_readfds);
		FD_SET(coap_fd, &m_readfds);
		nfds = coap_fd + 1;
	}

#ifdef _WIN32
	signal(SIGINT, handle_sigint);
#else
	memset (&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = handle_sigint;
	sa.sa_flags = 0;
	sigaction (SIGINT, &sa, NULL);
	sigaction (SIGTERM, &sa, NULL);
	/* So we do not exit on a SIGPIPE */
	sa.sa_handler = SIG_IGN;
	sigaction (SIGPIPE, &sa, NULL);
#endif

	wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

	while ( !quit ) {
		int result;

		if (coap_fd != -1) {
			fd_set readfds = m_readfds;
			struct timeval tv;

			tv.tv_sec = wait_ms / 1000;
			tv.tv_usec = (wait_ms % 1000) * 1000;
			/* Wait until any i/o takes place */
			result = select (nfds, &readfds, NULL, NULL, &tv);
			if (result == -1) {
				if (errno != EAGAIN) {
					coap_log(LOG_DEBUG, "select: %s (%d)\n", coap_socket_strerror(), errno);
					break;
				}
			}
			if (result > 0) {
				if (FD_ISSET(coap_fd, &readfds)) {
					result = coap_io_process(ctx, COAP_RUN_NONBLOCK);
				}
			}
		}
		else {
			/* epoll is not supported within libcoap */
			result = coap_io_process(ctx, wait_ms);
		}
		if ( result < 0 ) {
			break;
		} else if ( result && (unsigned)result < wait_ms ) {
			/* decrement if there is a result wait time returned */
			wait_ms -= result;
		} else {
			/*
			 * result == 0, or result >= wait_ms
			 * (wait_ms could have decremented to a small value, below
			 * the granularity of the timer in coap_io_process() and hence
			 * result == 0)
			 */
			time_t t_now = time(NULL);
			if (t_last != t_now) {
				/* Happens once per second */
				t_last = t_now;
				if (time_resource) {
					coap_resource_notify_observers(time_resource, NULL);
				}
			}
			if (result) {
				/* result must have been >= wait_ms, so reset wait_ms */
				wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
			}
		}

#ifndef WITHOUT_ASYNC
		/* check if we have to send asynchronous responses */
		coap_ticks( &now );
		check_async(ctx, now);
#endif /* WITHOUT_ASYNC */
	}



	coap_free_context(ctx);
	coap_cleanup();

	return 0;
}

