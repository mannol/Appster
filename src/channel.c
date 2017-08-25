#include "channel.h"
#include <libdill.h>
#include <stdio.h>

channel_t ch_make() {
    channel_t ch;
    ch.id = chmake(sizeof(void*));
    if(ch.id == -1) {
        perror("Cannot create channel");
        exit(1);
    }
    return ch;
}
void ch_close(channel_t ch) {
    hclose(ch.id);
}
channel_t ch_from_ptr(void* ptr) {
    channel_t ch;
    ch.ptr = (uintptr_t) ptr;
    return ch;
}
channel_t ch_from_int(int i) {
    channel_t ch;
    ch.id = i;
    return ch;
}
void ch_send(channel_t ch, void* what) {
    if(chsend(ch.id, &what, sizeof(void*), -1) != 0) {
        perror("Cannot send a message");
        exit(1);
    }
    yield();
}
void* ch_recv(channel_t ch) {
    void* rc;
    if(chrecv(ch.id, &rc, sizeof(void*), -1) != 0) {
        perror("Cannot receive message");
        exit(1);
    }
    hclose(ch.id);
    return rc;
}
void* ch_pass(channel_t ch) {
    void* rc;
    if(chrecv(ch.id, &rc, sizeof(void*), -1) != 0) {
        perror("Cannot receive message");
        exit(1);
    }
    return rc;
}
int ch_good(channel_t ch) {
    return ch.id != -1;
}
