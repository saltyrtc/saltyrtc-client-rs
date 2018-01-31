/**
 * C integration test.
 */
#include <stdio.h>

#include "../saltyrtc_client_ffi.h"

int main() {
    printf("START C TESTS\n");

    printf("  Creating key pair\n");
    salty_keypair_t *keypair = salty_keypair_new();

    printf("  Creating event loop\n");
    salty_event_loop_t *loop = salty_event_loop_new();

    printf("  Getting event loop remote handle\n");
    salty_remote_t *remote = salty_event_loop_get_remote(loop);

    printf("  Freeing event loop remote handle\n");
    salty_event_loop_free_remote(remote);

    printf("  Freeing event loop\n");
    salty_event_loop_free(loop);

    printf("  Freeing key pair\n");
    salty_keypair_free(keypair);

    printf("END C TESTS\n");
}