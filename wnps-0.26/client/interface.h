/*
    interface.h for interface.c
    
    (c) 2007    wzt
*/

#ifndef INTERFACE_H
#define INTERFACE_H

#define DEBUG

#define NAME            30

char    inter_face[NAME];    /* bind port with  interface */

int check_interface(char *devname);
void show_interface(char *devname);
void find_interface();

#endif  /* __INTERFACE_H__ */
