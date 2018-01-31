/**
 * C bindings for saltyrtc-client crate.
 * https://github.com/saltyrtc/saltyrtc-client-ffi-rs
 **/

#ifndef saltyrtc_client_bindings_h
#define saltyrtc_client_bindings_h

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

/*
 * FFI representation of a trait object.
 * See https://stackoverflow.com/a/33929480/284318
 */
typedef struct FFITraitObject FFITraitObject;

/*
 * An event loop instance.
 */
typedef struct salty_event_loop_t salty_event_loop_t;

/*
 * A key pair.
 */
typedef struct salty_keypair_t salty_keypair_t;

/*
 * A remote handle to an event loop instance.
 */
typedef struct salty_remote_t salty_remote_t;

/*
 * A task instance.
 */
typedef FFITraitObject salty_task_t;

/*
 * Free an event loop instance.
 */
void salty_event_loop_free(salty_event_loop_t *ptr);

/*
 * Free an event loop remote handle.
 */
void salty_event_loop_free_remote(salty_remote_t *ptr);

/*
 * Return a remote handle from an event loop instance.
 *
 * Thread safety:
 *     The `salty_remote_t` instance may be used from any thread.
 * Returns:
 *     A reference to the remote handle.
 *     If the pointer passed in is `null`, an error is logged and `null` is returned.
 */
salty_remote_t *salty_event_loop_get_remote(salty_event_loop_t *ptr);

/*
 * Create a new event loop instance.
 *
 * In the background, this will instantiate a Tokio reactor core.
 *
 * Returns:
 *     Either a pointer to the reactor core, or `null`
 *     if creation of the event loop failed.
 *     In the case of a failure, the error will be logged.
 */
salty_event_loop_t *salty_event_loop_new(void);

/*
 * Free a `KeyPair` instance.
 */
void salty_keypair_free(salty_keypair_t *ptr);

/*
 * Create a new `KeyPair` instance and return an opaque pointer to it.
 */
salty_keypair_t *salty_keypair_new(void);

#endif /* saltyrtc_client_bindings_h */
