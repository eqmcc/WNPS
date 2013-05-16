/* 
	socket.c	(c) 2007	wzt
*/

#include "socket.h"

/* connect remote ip:port */

int connect_ip(int ip,int port)
{
	struct sockaddr_in		serv_addr;
	int						sock_fd;

	if( (sock_fd = socket(AF_INET,SOCK_STREAM,0)) == -1 ){
		perror("[-] socket");
		exit(0);
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = port;
	serv_addr.sin_addr.s_addr = ip;

	if( connect(sock_fd,(struct sockaddr *)&serv_addr,sizeof(struct sockaddr)) == -1 ){
#ifdef DEBUG
		printf("[-] connect\n");
#endif
		return 0;
	}
	
	return sock_fd;
}

/* bind a local port */
int listen_port(int port)
{
	struct sockaddr_in		my_addr,remote_addr;
	int						sock_fd,sock_id;
	int						size,flag = 1;

	if( (sock_fd = socket(AF_INET,SOCK_STREAM,0)) == -1 ){
		perror("[-] socket");
		exit(1);
	}

	my_addr.sin_family = AF_INET;
	my_addr.sin_port = port;
	my_addr.sin_addr.s_addr = 0;

        setsockopt(sock_fd,SOL_SOCKET,SO_REUSEADDR, (char*)&flag,sizeof(flag));

	if( bind(sock_fd,(struct sockaddr *)&my_addr,sizeof(struct sockaddr)) == -1 ){
		perror("[-] bind");
		exit(1);
	}

	if( listen(sock_fd,5) == -1 ){
		perror("[-] listen");
		exit(1);
	}

	size = sizeof(struct sockaddr_in);
	if( (sock_id = accept(sock_fd,(struct sockaddr *)&remote_addr,&size)) == -1 ){		
		perror("[-] accept");
		return 0;
	}

	return sock_id;
}

