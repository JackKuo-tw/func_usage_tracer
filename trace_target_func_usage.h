/* ******************************************************************************
 * Copyright (c) 2011-2018 Google, Inc.  All rights reserved.
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
 * instrace_simple.c
 *
 * Collects a dynamic instruction trace and dumps it to a text file.
 * This is a simpler (and slower) version of instrace_x86.c.
 *
 * (1) It fills a per-thread-buffer from inlined instrumentation.
 * (2) It calls a clean call to dump the buffer into a file.
 *
 * The trace is a simple text file with each line containing the PC and
 * the opcode of the instruction.
 *
 * This client is a simple implementation of an instruction tracing tool
 * without instrumentation optimization.  It also uses simple absolute PC
 * values and does not separate them into library offsets.
 * Additionally, dumping as text is much slower than dumping as
 * binary.  See instrace_x86.c for a higher-performance sample.
 */

#ifndef TRACE_TARGET_FUNC_USAGE_H
#    define TRACE_TARGET_FUNC_USAGE_H
#endif

#include <stdio.h>
#include <stddef.h> /* for offsetof */
#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#include "drreg.h"
#include "drsyms.h"
#include "drutil.h"
#include "utils.h"
#include "string.h"

#define TLS_SLOT(tls_base, enum_val) \
    (void **)((byte *)(tls_base) + tls_offs + (enum_val)*8)
#define BUF_PTR(tls_base) *(mem_ref_t **)TLS_SLOT(tls_base, MEMTRACE_TLS_OFFS_BUF_PTR)

#define MINSERT instrlist_meta_preinsert

/* Max number of mem_ref a buffer can have. It should be big enough
 * to hold all entries between clean calls.
 */
#define MAX_NUM_MEM_REFS 8192
/* The maximum size of buffer for holding mem_refs. */
#define MEM_BUF_SIZE_MEM_R (sizeof(mem_ref_t) * MAX_NUM_MEM_REFS)

// per thread only
// set -1 means unlimited
#define MAX_RECORD_TIME 100

/* Each mem_ref_t is a <type, size, addr> entry representing a memory reference
 * instruction or the reference information, e.g.:
 * - mem ref instr: { type = 42 (call), size = 5, addr = 0x7f59c2d002d3 }
 * - mem ref info:  { type = 1 (write), size = 8, addr = 0x7ffeacab0ec8 }
 */
typedef struct _mem_ref_t {
    ushort type; /* r(0), w(1), or opcode (assuming 0/1 are invalid opcode) */
    ushort size; /* mem ref size or instr length */
    app_pc addr; /* mem ref addr or instr pc */
} mem_ref_t;

/* Each ins_ref_t describes an executed instruction. */
typedef struct _ins_ref_t {
    app_pc pc;
    int opcode;
} ins_ref_t;

/* thread private log file and counter */
typedef struct {
    byte *seg_base;
    mem_ref_t *buf_base_mem;
    ins_ref_t *buf_base_ins;
    file_t log;
    FILE *logf;
    uint64 num_refs_mem;
    uint64 num_refs_target_mem;
    uint64 num_refs_ins;
    uint64 num_refs_target_ins;
    bool is_tracing;
    uint64 func_trigger_times;
} per_thread_t;

bool wrapped;
static client_id_t client_id;
static void *mutex;         /* for multithread support */
static uint64 num_refs_mem; /* keep a global memory reference count */
static uint64 num_refs_ins; /* keep a global instruction reference count */
static uint64 num_refs_target_mem; /* keep a global memory reference count */
static uint64 num_refs_target_ins; /* keep a global instruction reference count */

static reg_id_t tls_seg;
static uint tls_offs;
static int tls_idx;

const char *app_name;
char *app_path;
dr_app_arg_t app_args;

void
get_app_name();
static void
wrap_pre(void *wrapcxt, OUT void **user_data);
static void
wrap_post(void *wrapcxt, void *user_data);
