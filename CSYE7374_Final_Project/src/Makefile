coap_server: coap_server.o I2C.o
	gcc -o coap_server coap_server.o I2C.o -lcoap-2

coap_server.o: I2C.h
	gcc -c coap_server.c  

I2C.o: I2C.h
	gcc -c I2C.c

clean:
	rm -f *.o
