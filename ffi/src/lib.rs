//! FFI bindings for the `saltyrtc-client` crate.
//!
//! The implementation makes use of the opaque pointer pattern.
//!
//! Note: These bindings should not be used directly to build a native library,
//! instead a custom library crate should inherit from both this crate and
//! from the task FFI crate.
//!
//! That's also why only some of the types are exposed. It's not currently
//! meant as a full FFI bindings solution, it only provides some common
//! building blocks.
//!
//! While the library generates a C header file, this is primarily meant
//! for testing. FFI crates inheriting from this crate should probably
//! re-export all relevant types and generate their own header files.
#![allow(non_camel_case_types)]

#[macro_use] extern crate log;

use std::boxed::Box;
use std::ptr;

use saltyrtc_client::crypto::KeyPair;
use tokio_core::reactor::{Core, Remote};


// *** TYPES *** //

/// A key pair.
#[no_mangle]
pub enum salty_keypair_t {}

/// An event loop instance.
#[no_mangle]
pub enum salty_event_loop_t {}

/// A remote handle to an event loop instance.
#[no_mangle]
pub enum salty_remote_t {}

/// A SaltyRTC client instance.
#[no_mangle]
pub enum salty_client_t {}


// *** KEY PAIRS *** //

/// Create a new `KeyPair` instance and return an opaque pointer to it.
#[no_mangle]
pub extern "C" fn salty_keypair_new() -> *mut salty_keypair_t {
    Box::into_raw(Box::new(KeyPair::new())) as *mut salty_keypair_t
}

/// Free a `KeyPair` instance.
#[no_mangle]
pub unsafe extern "C" fn salty_keypair_free(ptr: *mut salty_keypair_t) {
    if ptr.is_null() {
        warn!("Tried to free a null pointer");
        return;
    }
    Box::from_raw(ptr as *mut KeyPair);
}


// *** EVENT LOOP *** //

/// Create a new event loop instance.
///
/// In the background, this will instantiate a Tokio reactor core.
///
/// Returns:
///     Either a pointer to the reactor core, or `null`
///     if creation of the event loop failed.
///     In the case of a failure, the error will be logged.
#[no_mangle]
pub extern "C" fn salty_event_loop_new() -> *mut salty_event_loop_t {
    match Core::new() {
        Ok(reactor) => Box::into_raw(Box::new(reactor)) as *mut salty_event_loop_t,
        Err(e) => {
            error!("Error: Could not create reactor core: {}", e);
            ptr::null_mut()
        }
    }
}

/// Return a remote handle from an event loop instance.
///
/// Thread safety:
///     The `salty_remote_t` instance may be used from any thread.
/// Returns:
///     A reference to the remote handle.
///     If the pointer passed in is `null`, an error is logged and `null` is returned.
#[no_mangle]
pub unsafe extern "C" fn salty_event_loop_get_remote(ptr: *mut salty_event_loop_t) -> *mut salty_remote_t {
    if ptr.is_null() {
        error!("Called salty_event_loop_get_remote on a null pointer");
        return ptr::null_mut();
    }
    let core = ptr as *mut Core;
    Box::into_raw(Box::new((*core).remote())) as *mut salty_remote_t
}

/// Free an event loop remote handle.
#[no_mangle]
pub unsafe extern "C" fn salty_event_loop_free_remote(ptr: *mut salty_remote_t) {
    if ptr.is_null() {
        warn!("Tried to free a null pointer");
        return;
    }
    Box::from_raw(ptr as *mut Remote);
}

/// Free an event loop instance.
#[no_mangle]
pub unsafe extern "C" fn salty_event_loop_free(ptr: *mut salty_event_loop_t) {
    if ptr.is_null() {
        warn!("Tried to free a null pointer");
        return;
    }
    Box::from_raw(ptr as *mut Core);
}
