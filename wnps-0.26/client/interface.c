#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "socket.h"
#include "interface.h"
#include "config.h"

extern char local_ip[20];

/* display interface information */
void show_interface(char *devname)
{
        struct sockaddr_in *addr;
        struct ifreq        ifr;
        int                 sock_id;

        sock_id = socket( AF_INET,SOCK_DGRAM,0 );
        strncpy( ifr.ifr_name,devname,IFNAMSIZ );

        if (ioctl( sock_id,SIOCGIFADDR,&ifr) == -1) {
                perror("[-] ioctl");
                exit(1);
        }

        addr = (struct sockaddr_in *) & ifr.ifr_addr;

        if (!strcmp(devname,DEFAULT_INTERFACE))
                sprintf(local_ip,"%s",inet_ntoa(addr->sin_addr));

        if (ioctl( sock_id,SIOCGIFBRDADDR,&ifr) == -1) {
                perror("[-] ioctl");
                exit(1);
        }

        addr = (struct sockaddr_in *) & (ifr.ifr_broadaddr);
    
        if (ioctl( sock_id,SIOCGIFNETMASK,&ifr) == -1) {
                perror("[-] ioctl");
                exit(1);
        }
}

/* find all active interface */
void find_interface()
{
    struct ifconf   ifc;
    struct ifreq    ifr;
    struct ifreq    *pifr;
    int             len, lastlen;
    int             i;
    int             fd;
    char            *buf;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("[-] socket \n");
        exit(1);
    }

    len = 10 * sizeof(struct ifreq);

    while (1) {
        buf = (char *)malloc(len);
        ifc.ifc_len = len;
        ifc.ifc_buf = buf;

        if (ioctl(fd, SIOCGIFCONF, &ifc) < 0) {
            if (errno != EINVAL || lastlen != 0) {
                perror("ioctl \n");
                free(buf);
                exit(1);
            }
        }
        else {
            if (ifc.ifc_len == lastlen)
                break;
            lastlen = ifc.ifc_len;
        }

        len += 5 * sizeof(struct ifreq);
        free(buf);
    }

    pifr = ifc.ifc_req;

    for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0 ; ++pifr) {
        strcpy(ifr.ifr_name, pifr->ifr_name);
        if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
            if (!(ifr.ifr_flags & IFF_LOOPBACK))
                show_interface(ifr.ifr_name);
        }
    }
}

