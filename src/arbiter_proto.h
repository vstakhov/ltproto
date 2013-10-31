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

#ifndef ARBITER_PROTO_H_
#define ARBITER_PROTO_H_

/**
 * @file
 * This file describes common structures used for shared memory arbiter protocol
 */

#define LT_ARBITER_NAME 64

enum ltproto_arbiter_msg_type {
	LT_ARBITER_REGISTER = 0x1,//!< LT_ARBITER_REGISTER
	LT_ARBITER_CONNECT = 0x2,  //!< LT_ARBITER_CONNECT
	LT_ARBITER_UNREGISTER = 0x3,//!< LT_ARBITER_UNREGISTER
	LT_ARBITER_SEND_FD = 0x4,
	LT_ARBITER_SUCCESS = 0x5,
	LT_ARBITER_ERROR = 0x6
};


struct ltproto_arbiter_msg {
	uint32_t msg;
	uint32_t msg_len;
	char name[LT_ARBITER_NAME];
	char payload[0];
};

#endif /* ARBITER_PROTO_H_ */
