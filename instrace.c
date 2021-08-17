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

#include "instrace.h"

// static int tls_idx;
// #define TLS_SLOT(tls_base, enum_val) (void **)((byte *)(tls_base) + tls_offs +
// (enum_val))
#define BUF_PTR_INS(tls_base) *(ins_ref_t **)TLS_SLOT(tls_base, INSTRACE_TLS_OFFS_BUF_PTR)

#define MINSERT instrlist_meta_preinsert

static void
instrace(void *drcontext)
{
    per_thread_t *data;
    ins_ref_t *ins_ref, *buf_ptr;

    data = drmgr_get_tls_field(drcontext, tls_idx);
    buf_ptr = BUF_PTR_INS(data->seg_base); // buf_ptr = (void **)((byte *)(data->seg_base)
                                           // + tls_offs + (INSTRACE_TLS_OFFS_BUF_PTR) * 8)
    /* Example of dumped file content:
     *   0x7f59c2d002d3: call
     *   0x7ffeacab0ec8: mov
     */
    /* We use libc's fprintf as it is buffered and much faster than dr_fprintf
     * for repeated printing that dominates performance, as the printing does here.
     */
    for (ins_ref = (ins_ref_t *)data->buf_base_ins; ins_ref < buf_ptr; ins_ref++) {
        if(data->is_tracing && (data->func_trigger_times == -1 || data->func_trigger_times <= MAX_RECORD_TIME)) {
            data->num_refs_target_ins++;
            /* We use PIFX to avoid leading zeroes and shrink the resulting file. */
            fprintf(data->logf, PIFX ": %s\n", (ptr_uint_t)ins_ref->pc,
                    decode_opcode_name(ins_ref->opcode));
        }
        
        data->num_refs_ins++;
    }
    BUF_PTR_INS(data->seg_base) = data->buf_base_ins;
}

/* clean_call dumps the memory reference info to the log file */
static void
clean_call_ins(void)
{
    void *drcontext = dr_get_current_drcontext();
    instrace(drcontext);
}

static void
insert_load_buf_ptr_ins(void *drcontext, instrlist_t *ilist, instr_t *where,
                        reg_id_t reg_ptr)
{
    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg,
                           tls_offs + INSTRACE_TLS_OFFS_BUF_PTR * 8, reg_ptr);
}

static void
insert_update_buf_ptr_ins(void *drcontext, instrlist_t *ilist, instr_t *where,
                          reg_id_t reg_ptr, int adjust)
{
    MINSERT(
        ilist, where,
        XINST_CREATE_add(drcontext, opnd_create_reg(reg_ptr), OPND_CREATE_INT16(adjust)));
    dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg,
                            tls_offs + INSTRACE_TLS_OFFS_BUF_PTR * 8, reg_ptr);
}

static void
insert_save_opcode_ins(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t base,
                       reg_id_t scratch, int opcode)
{
    scratch = reg_resize_to_opsz(scratch, OPSZ_2);
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(scratch),
                                  OPND_CREATE_INT16(opcode)));
    MINSERT(ilist, where,
            XINST_CREATE_store_2bytes(
                drcontext, OPND_CREATE_MEM16(base, offsetof(ins_ref_t, opcode)),
                opnd_create_reg(scratch)));
}

static void
insert_save_pc_ins(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t base,
                   reg_id_t scratch, app_pc pc)
{
    instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t)pc, opnd_create_reg(scratch),
                                     ilist, where, NULL, NULL);
    MINSERT(ilist, where,
            XINST_CREATE_store(drcontext,
                               OPND_CREATE_MEMPTR(base, offsetof(ins_ref_t, pc)),
                               opnd_create_reg(scratch)));
}

/* insert inline code to add an instruction entry into the buffer */
static void
instrument_instr_ins(void *drcontext, instrlist_t *ilist, instr_t *where)
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

    insert_load_buf_ptr_ins(drcontext, ilist, where, reg_ptr);
    insert_save_pc_ins(drcontext, ilist, where, reg_ptr, reg_tmp,
                       instr_get_app_pc(where));
    insert_save_opcode_ins(drcontext, ilist, where, reg_ptr, reg_tmp,
                           instr_get_opcode(where));
    insert_update_buf_ptr_ins(drcontext, ilist, where, reg_ptr, sizeof(ins_ref_t));

    /* Restore scratch registers */
    if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS)
        DR_ASSERT(false);
}

