# Project
project('saltyrtc-client-ffi-tests', 'c')

# Dependencies
compiler = meson.get_compiler('c')
rust_target_dir = join_paths(meson.source_root(), 'target/debug/')
saltyrtc_client_ffi = compiler.find_library('saltyrtc_client_ffi', dirs : [rust_target_dir])

# Executables
executable('tests', 'tests/tests.c', dependencies : [saltyrtc_client_ffi])
