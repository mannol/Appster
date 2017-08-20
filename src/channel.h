#ifndef CHANNEL_H
#define CHANNEL_H

#include <stdint.h>

typedef union channel_u
{
    uintptr_t ptr;
    int id;
} channel_t;

channel_t ch_make();
channel_t ch_from_ptr(void* ptr);
channel_t ch_from_int(int i);
void ch_send(channel_t ch, void* what);
void* ch_recv(channel_t ch);

#endif // CHANNEL_H
