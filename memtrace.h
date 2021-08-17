/* ******************************************************************************
 * Copyright (c) 2011-2021 Google, Inc.  All rights reserved.
 * Copyright (c) 2010 Massachusetts Institute of Technology  All rights reserved.
 * ******************************************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* Code Manipulation API Sample:
 * memtrace_simple.c
 *
 * Collects the memory reference information and dumps it to a file as text.
 *
 * (1) It fills a per-thread-buffer with inlined instrumentation.
 * (2) It calls a clean call to dump the buffer into a file.
 *
 * The profile consists of list of <type, size, addr> entries representing
 * - mem ref instr: e.g., { type = 42 (call), size = 5, addr = 0x7f59c2d002d3 }
 * - mem ref info:  e.g., { type = 1 (write), size = 8, addr = 0x7ffeacab0ec8 }.
 *
 * Each memory-referencing instruction is output as an instruction entry followed
 * by a sequence of loads and stores performed by that instruction, if any.
 *
 * This sample illustrates
 * - the use of drutil_expand_rep_string() to expand string loops to obtain
 *   every memory reference;
 * - the use of drx_expand_scatter_gather() to expand scatter/gather instrs
 *   into a set of functionally equivalent stores/loads;
 * - the use of drutil_opnd_mem_size_in_bytes() to obtain the size of OP_enter
 *   memory references;
 * - the use of drutil_insert_get_mem_addr() to insert instructions to compute
 *   the address of each memory reference.
 *
 * This client is a simple implementation of a memory reference tracing tool
 * without instrumentation optimization.  Additionally, dumping as
 * text is much slower than dumping as binary.  See memtrace_x86.c for
 * a higher-performance sample.
 */

#ifndef MEMTRACE_H
#    define MEMTRACE_H
#endif

#ifndef TRACE_TARGET_FUNC_USAGE_H
#    include "trace_target_func_usage.h"
#endif

extern reg_id_t tls_seg;
extern uint tls_offs;

enum {
    REF_TYPE_READ = 0,
    REF_TYPE_WRITE = 1,
};

/* Allocated TLS slot offsets */
enum {
    MEMTRACE_TLS_OFFS_BUF_PTR,
    INSTRACE_TLS_OFFS_BUF_PTR,
    MEMTRACE_TLS_COUNT, /* total number of TLS slots allocated */
};
