/* socket.h	(c)	2007	wzt */

#ifndef SOCKET_H
#define SOCKET_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>

int connect_ip(int ip,int port);
int listen_port(int port);

#endif	/* _SOCKET_H_ */

