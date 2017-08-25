#ifndef CHANNEL_H
#define CHANNEL_H

#include <stdint.h>

typedef union channel_u
{
    uintptr_t ptr;
    int id;
} channel_t;

channel_t ch_make();
void ch_close(channel_t ch);
channel_t ch_from_ptr(void* ptr);
channel_t ch_from_int(int i);
void ch_send(channel_t ch, void* what);
void* ch_recv(channel_t ch);
void* ch_pass(channel_t ch);
int ch_good(channel_t ch); // returns non-zero if good

#endif // CHANNEL_H
