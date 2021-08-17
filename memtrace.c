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

#include "memtrace.h"

static void
memtrace(void *drcontext)
{
    per_thread_t *data;
    mem_ref_t *mem_ref, *buf_ptr;

    data = drmgr_get_tls_field(drcontext, tls_idx);
    buf_ptr = BUF_PTR(data->seg_base);
    /* Example of dumpped file content:
     *   0x00007f59c2d002d3:  5, call
     *   0x00007ffeacab0ec8:  8, w
     */
    /* We use libc's fprintf as it is buffered and much faster than dr_fprintf
     * for repeated printing that dominates performance, as the printing does here.
     */
    for (mem_ref = (mem_ref_t *)data->buf_base_mem; mem_ref < buf_ptr; mem_ref++) {
        /* We use PIFX to avoid leading zeroes and shrink the resulting file. */
        if (data->is_tracing && (data->func_trigger_times == -1 || data->func_trigger_times <= MAX_RECORD_TIME)) {
            data->num_refs_target_mem++;
            fprintf(data->logf, "" PIFX ": %s, %-2d\n", (ptr_uint_t)mem_ref->addr,
                    (mem_ref->type > REF_TYPE_WRITE)
                        ? decode_opcode_name(mem_ref->type) /* opcode for instr */
                        : (mem_ref->type == REF_TYPE_WRITE ? "w" : "r"),  mem_ref->size);
        }
        data->num_refs_mem++;
    }
    BUF_PTR(data->seg_base) = data->buf_base_mem;
}

static void
insert_load_buf_ptr_mem(void *drcontext, instrlist_t *ilist, instr_t *where,
                        reg_id_t reg_ptr)
{
    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg,
                           tls_offs + MEMTRACE_TLS_OFFS_BUF_PTR, reg_ptr);
}

static void
insert_update_buf_ptr_mem(void *drcontext, instrlist_t *ilist, instr_t *where,
                          reg_id_t reg_ptr, int adjust)
{
    MINSERT(
        ilist, where,
        XINST_CREATE_add(drcontext, opnd_create_reg(reg_ptr), OPND_CREATE_INT16(adjust)));
    dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg,
                            tls_offs + MEMTRACE_TLS_OFFS_BUF_PTR, reg_ptr);
}

static void
insert_save_type_mem(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t base,
                     reg_id_t scratch, ushort type)
{
    scratch = reg_resize_to_opsz(scratch, OPSZ_2);
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(scratch),
                                  OPND_CREATE_INT16(type)));
    MINSERT(ilist, where,
            XINST_CREATE_store_2bytes(drcontext,
                                      OPND_CREATE_MEM16(base, offsetof(mem_ref_t, type)),
                                      opnd_create_reg(scratch)));
}

static void
insert_save_size_mem(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t base,
                     reg_id_t scratch, ushort size)
{
    scratch = reg_resize_to_opsz(scratch, OPSZ_2);
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(scratch),
                                  OPND_CREATE_INT16(size)));
    MINSERT(ilist, where,
            XINST_CREATE_store_2bytes(drcontext,
                                      OPND_CREATE_MEM16(base, offsetof(mem_ref_t, size)),
                                      opnd_create_reg(scratch)));
}

static void
insert_save_pc_mem(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t base,
                   reg_id_t scratch, app_pc pc)
{
    instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t)pc, opnd_create_reg(scratch),
                                     ilist, where, NULL, NULL);
    MINSERT(ilist, where,
            XINST_CREATE_store(drcontext,
                               OPND_CREATE_MEMPTR(base, offsetof(mem_ref_t, addr)),
                               opnd_create_reg(scratch)));
}

static void
insert_save_addr_mem(void *drcontext, instrlist_t *ilist, instr_t *where, opnd_t ref,
                     reg_id_t reg_ptr, reg_id_t reg_addr)
{
    bool ok;
    /* we use reg_ptr as scratch to get addr */
    ok = drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg_addr, reg_ptr);
    DR_ASSERT(ok);
    insert_load_buf_ptr_mem(drcontext, ilist, where, reg_ptr);
    MINSERT(ilist, where,
            XINST_CREATE_store(drcontext,
                               OPND_CREATE_MEMPTR(reg_ptr, offsetof(mem_ref_t, addr)),
                               opnd_create_reg(reg_addr)));
}

/* insert inline code to add an instruction entry into the buffer */
static void
instrument_instr_mem(void *drcontext, instrlist_t *ilist, instr_t *where)
{
    /* We need two scratch registers */
    reg_id_t reg_ptr, reg_tmp;
    /* we don't want to predicate this, because an instruction fetch always occurs */
    instrlist_set_auto_predicate(ilist, DR_PRED_NONE);
    if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) !=
            DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) !=
            DRREG_SUCCESS) {
        DR_ASSERT(false); /* cannot recover */
        return;
    }
    insert_load_buf_ptr_mem(drcontext, ilist, where, reg_ptr);
    insert_save_type_mem(drcontext, ilist, where, reg_ptr, reg_tmp,
                         (ushort)instr_get_opcode(where));
    insert_save_size_mem(drcontext, ilist, where, reg_ptr, reg_tmp,
                         (ushort)instr_length(drcontext, where));
    insert_save_pc_mem(drcontext, ilist, where, reg_ptr, reg_tmp,
                       instr_get_app_pc(where));
    insert_update_buf_ptr_mem(drcontext, ilist, where, reg_ptr, sizeof(mem_ref_t));
    /* Restore scratch registers */
    if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS)
        DR_ASSERT(false);
    instrlist_set_auto_predicate(ilist, instr_get_predicate(where));
}

/* insert inline code to add a memory reference info entry into the buffer */
static void
instrument_mem(void *drcontext, instrlist_t *ilist, instr_t *where, opnd_t ref,
               bool write)
{
    /* We need two scratch registers */
    reg_id_t reg_ptr, reg_tmp;
    if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) !=
            DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) !=
            DRREG_SUCCESS) {
        DR_ASSERT(false); /* cannot recover */
        return;
    }
    /* save_addr should be called first as reg_ptr or reg_tmp maybe used in ref */
    insert_save_addr_mem(drcontext, ilist, where, ref, reg_ptr, reg_tmp);
    insert_save_type_mem(drcontext, ilist, where, reg_ptr, reg_tmp,
                         write ? REF_TYPE_WRITE : REF_TYPE_READ);
    insert_save_size_mem(drcontext, ilist, where, reg_ptr, reg_tmp,
                         (ushort)drutil_opnd_mem_size_in_bytes(ref, where));
    insert_update_buf_ptr_mem(drcontext, ilist, where, reg_ptr, sizeof(mem_ref_t));
    /* Restore scratch registers */
    if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS)
        DR_ASSERT(false);
}
