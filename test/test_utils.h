/* Copyright (c) 2013, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef TEST_UTILS_H_
#define TEST_UTILS_H_

#include "config.h"

/**
 * Start time of some test
 * @param time_data opaque data that is used and allocated internally
 */
void start_test_time (void **time_data);

/**
 * Get time from start of a test
 * @param time_data opaque data that is used and deallocated internally
 * @return time in nanoseconds
 */
uint64_t end_test_time (void *time_data);

/**
 * Convert time to the nearest available double value according to clock resolution
 * @param nanoseconds input nanoseconds
 * @return milliseconds with fractional part
 */
double round_test_time (uint64_t nanoseconds);

/**
 * Fork server
 * @param port port to bind
 * @param recv_buffer_size size of receive buffer
 * @return 0 in case of success, -1 in case of error (and doesn't return for server process)
 */
pid_t fork_server (u_short port, u_int recv_buffer_size, void *mod, int corenum, int strict_check);

/**
 * Perform client test
 * @param port port to connect
 * @param send_buffer_size size of send buffer
 * @param repeat_count how many times this buffer should be sent
 * @return
 */
int do_client (u_short port, u_int send_buffer_size, u_int repeat_count, void *mod, const char *modname, int strict_check);


/**
 * Fork server to test latency
 * @param port port to bind
 * @param recv_buffer_size size of receive buffer
 * @return 0 in case of success, -1 in case of error (and doesn't return for server process)
 */
pid_t fork_server_latency (u_short port, void *mod, int corenum);

/**
 * Perform client test
 * @param port port to connect
 * @param send_buffer_size size of send buffer
 * @param repeat_count how many times this buffer should be sent
 * @return
 */
int do_client_latency (u_short port, void *mod, const char *modname, uint64_t *dest);


/**
 * Return humanized number of bytes
 * @param bytes bytes to print
 * @return static buffer with desired string
 */
char* print_bytes (uint64_t bytes);

/**
 * Return humanized number of nanoseconds
 * @param bytes bytes to print
 * @return static buffer with desired string
 */
char* print_nanoseconds (uint64_t nsec);


/**
 * Init google perftools
 * @param descr process description
 */
void gperf_profiler_init (const char *descr);

/**
 * Stop google perftools and write everything
 */
void gperf_profiler_stop (void);

/**
 * Bind this process to a specific core
 * @param corenum number of core
 */
void bind_to_core (int corenum);

#endif /* TEST_UTILS_H_ */
