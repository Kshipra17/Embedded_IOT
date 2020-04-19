/*
 * coap_server.h
 *
 *  Created on: Apr 18, 2020
 *      Author: Ksp
 */
//#include <coap2/coap.h>
#include "../Inc/I2C.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <coap2/coap.h>

int main(void) {
  coap_context_t  *ctx = NULL;
  coap_address_t dst;
  coap_resource_t *resource = NULL;
  coap_endpoint_t *endpoint = NULL;
  int result = EXIT_FAILURE;;
  coap_str_const_t *ruri = coap_make_str_const("temperature");
  coap_startup();
  int temperature =0;

  /* resolve destination address where server should be sent */
 /* if (resolve_address("localhost", "5683", &dst) < 0) {
    coap_log(LOG_CRIT, "failed to resolve address\n");
    goto finish;
  }*/

  /* create CoAP context and a client session */
  ctx = coap_new_context(NULL);

  if (!ctx || !(endpoint = coap_new_endpoint(ctx, &dst, COAP_PROTO_UDP))) {
    coap_log(LOG_EMERG, "cannot initialize context\n");
   goto finish;
 }

  resource = coap_resource_init(ruri, 0);
 // coap_register_handler(resource, COAP_REQUEST_GET, getTemperaturefromI2C);
// coap_register_handler(resource, COAP_REQUEST_PUT, hnd_put_time);

  coap_add_resource(ctx, resource);

  //while (1) { coap_run_once(ctx, 0); }

  result = EXIT_SUCCESS;
 finish:

  coap_free_context(ctx);
  coap_cleanup();

  return result;
}

