/*
 * coap_server.h
 *
 *  Created on: Apr 18, 2020
 *      Author: Ksp
 */
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include "../Inc/I2C.h"

int main(void) {
  coap_context_t  *ctx = nullptr;
  coap_address_t dst;
  coap_resource_t *resource = nullptr;
  coap_endpoint_t *endpoint = nullptr;
  int result = EXIT_FAILURE;;
  coap_str_const_t *ruri = coap_make_str_const("temperature");
  coap_startup();
  int temperature =0;

  /* resolve destination address where server should be sent */
  if (resolve_address("localhost", "5683", &dst) < 0) {
    coap_log(LOG_CRIT, "failed to resolve address\n");
    goto finish;
  }

  /* create CoAP context and a client session */
  ctx = coap_new_context(nullptr);

  if (!ctx || !(endpoint = coap_new_endpoint(ctx, &dst, COAP_PROTO_UDP))) {
    coap_log(LOG_EMERG, "cannot initialize context\n");
    goto finish;
  }

  resource = coap_resource_init(ruri, 0);
  coap_register_handler(resource, COAP_REQUEST_GET, getTemperaturefromI2C);
//  coap_register_handler(resource, COAP_REQUEST_PUT, hnd_put_time);

  coap_add_resource(ctx, resource);

  while (true) { coap_run_once(ctx, 0); }

  result = EXIT_SUCCESS;
 finish:

  coap_free_context(ctx);
  coap_cleanup();

  return result;
}

