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
 * This sample illustrates
 * - the use of drutil_expand_rep_string() to expand string loops to obtain
 *   every memory reference,
 * - the use of drutil_opnd_mem_size_in_bytes() to obtain the size of OP_enter
 *   memory references,
 * - the use of drutil_insert_get_mem_addr() to insert instructions to compute
 *   the address of each memory reference.
 *
 * This client is a simple implementation of a memory reference tracing tool
 * without instrumentation optimization.  Additionally, dumping as
 * text is much slower than dumping as binary.  See memtrace_x86.c for
 * a higher-performance sample.
 */

#include "trace_target_func_usage.h"
#include "memtrace.c"
#include "instrace.c"


#ifndef MAIN_TRACE_MEM
#    define MAIN_TRACE_INS
#    define MAIN_TRACE_MEM
#endif

char TARGET_FUNC_NAME[100];
/* clean_call_mem dumps the memory reference info to the log file */
static void
clean_call_mem(void)
{
    void *drcontext = dr_get_current_drcontext();
    memtrace(drcontext);
}

/* Wrap the target function with tracing indicator */
static void
module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
    if (wrapped == true)
        return;
    dr_printf("[INFO] App path: %s\n", app_path);
    size_t symbol_offset = 0;
    drsym_lookup_symbol(app_path, TARGET_FUNC_NAME, &symbol_offset, DRSYM_DEFAULT_FLAGS);
    dr_printf("[INFO] App path: %s\n", app_path);
    dr_printf("[INFO] The addr: %d\n", symbol_offset);
    module_data_t *module_data = dr_lookup_module_by_name(app_name);
    dr_printf("[INFO] The module base addr: %s\n", module_data->start);
    DR_ASSERT(module_data != NULL);
    if (symbol_offset != 0) {
#ifdef SHOW_RESULTS
        bool ok =
#endif
            drwrap_wrap((app_pc)(symbol_offset + (size_t)module_data->start), wrap_pre,
                        wrap_post);
#ifdef SHOW_RESULTS
        if (ok) {
            dr_fprintf(STDERR, "[INFO] Target function wrapped @ " PFX "\n",
                       (app_pc)symbol_offset);
        } else {
            /* We expect this w/ forwarded exports (e.g., on win7 both
             * kernel32!HeapAlloc and kernelbase!HeapAlloc forward to
             * the same routine in ntdll.dll)
             */
            dr_fprintf(STDERR,
                       "[ERROR] FAILED to wrap function @ " PFX
                       ": already wrapped?\n",
                       (app_pc)symbol_offset);
        }
#endif
    }
    wrapped = true;
}

static void
wrap_pre(void *wrapcxt, OUT void **user_data)
{
    per_thread_t *data;
    void *drcontext = dr_get_current_drcontext();
    data = drmgr_get_tls_field(drcontext, tls_idx);
    data->is_tracing = true;
    data->func_trigger_times += 1;
    if (data->func_trigger_times == -1 || data->func_trigger_times <= MAX_RECORD_TIME) {
        dr_printf("~~ Enter Target Function ~~\n");
        fprintf(data->logf, "~~ Enter Target Function ~~\n");
    }
}

static void
wrap_post(void *wrapcxt, void *user_data)
{
    per_thread_t *data;
    void *drcontext = dr_get_current_drcontext();
    data = drmgr_get_tls_field(drcontext, tls_idx);
    data->is_tracing = false;
    if (data->func_trigger_times == -1 || data->func_trigger_times <= MAX_RECORD_TIME) {
        dr_printf("== Leave Target Function ==\n");
        fprintf(data->logf, "== Leave Target Function ==\n");
    }
}

/* For each memory reference app instr, we insert inline code to fill the buffer
 * with an instruction entry and memory reference entries.
 */
static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data)
{
    int i;

    if (!instr_is_app(instr))
        return DR_EMIT_DEFAULT;
    if (!instr_reads_memory(instr) && !instr_writes_memory(instr))
        return DR_EMIT_DEFAULT;

    /* insert code to add an entry for app instruction */
    instrument_instr_mem(drcontext, bb, instr);

    /* insert code to add an entry for each memory reference opnd */
    for (i = 0; i < instr_num_srcs(instr); i++) {
        if (opnd_is_memory_reference(instr_get_src(instr, i)))
            instrument_mem(drcontext, bb, instr, instr_get_src(instr, i), false);
    }

    for (i = 0; i < instr_num_dsts(instr); i++) {
        if (opnd_is_memory_reference(instr_get_dst(instr, i)))
            instrument_mem(drcontext, bb, instr, instr_get_dst(instr, i), true);
    }

    /* insert code to call clean_call_mem for processing the buffer */
    if (/* XXX i#1698: there are constraints for code between ldrex/strex pairs,
         * so we minimize the instrumentation in between by skipping the clean call.
         * As we're only inserting instrumentation on a memory reference, and the
         * app should be avoiding memory accesses in between the ldrex...strex,
         * the only problematic point should be before the strex.
         * However, there is still a chance that the instrumentation code may clear the
         * exclusive monitor state.
         * Using a fault to handle a full buffer should be more robust, and the
         * forthcoming buffer filling API (i#513) will provide that.
         */
        IF_AARCHXX_ELSE(!instr_is_exclusive_store(instr), true))
        dr_insert_clean_call(drcontext, bb, instr, (void *)clean_call_mem, false, 0);

    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_app_instruction2(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                       bool for_trace, bool translating, void *user_data)
{
    drmgr_disable_auto_predication(drcontext, bb);

    if (!instr_is_app(instr))
        return DR_EMIT_DEFAULT;

    /* insert code to add an entry to the buffer */
    instrument_instr_ins(drcontext, bb, instr);

    /* insert code once per bb to call clean_call for processing the buffer */
    if (drmgr_is_first_instr(drcontext, instr)
        /* XXX i#1698: there are constraints for code between ldrex/strex pairs,
         * so we minimize the instrumentation in between by skipping the clean call.
         * We're relying a bit on the typical code sequence with either ldrex..strex
         * in the same bb, in which case our call at the start of the bb is fine,
         * or with a branch in between and the strex at the start of the next bb.
         * However, there is still a chance that the instrumentation code may clear the
         * exclusive monitor state.
         * Using a fault to handle a full buffer should be more robust, and the
         * forthcoming buffer filling API (i#513) will provide that.
         */
        IF_AARCHXX(&&!instr_is_exclusive_store(instr)))
        dr_insert_clean_call(drcontext, bb, instr, (void *)clean_call_ins, false, 0);

    return DR_EMIT_DEFAULT;
}

/* We transform string loops into regular loops so we can more easily
 * monitor every memory reference they make.
 */
static dr_emit_flags_t
event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                 bool translating)
{
    // if (!drutil_expand_rep_string(drcontext, bb)) {
    //     DR_ASSERT(false);
    //     /* in release build, carry on: we'll just miss per-iter refs */
    // }
    return DR_EMIT_DEFAULT;
}

static void
event_thread_init(void *drcontext)
{
    per_thread_t *data = dr_thread_alloc(drcontext, sizeof(per_thread_t));
    DR_ASSERT(data != NULL);
    /* store it in the slot provided in the drcontext */
    drmgr_set_tls_field(drcontext, tls_idx, data);

    /* Keep seg_base in a per-thread data structure so we can get the TLS
     * slot and find where the pointer points to in the buffer.
     */
    data->seg_base = dr_get_dr_segment_base(tls_seg);
    data->buf_base_mem =
        dr_raw_mem_alloc(MEM_BUF_SIZE_MEM_R, DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
    data->buf_base_ins =
        dr_raw_mem_alloc(MEM_BUF_SIZE_INS_R, DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
    DR_ASSERT(data->seg_base != NULL && data->buf_base_mem != NULL);
    /* put buf_base to TLS as starting buf_ptr */
    BUF_PTR(data->seg_base) =
        data->buf_base_mem; // *(mem_ref_t **) (void **)((byte *)(data->seg_base) +
                            // tls_offs + (MEMTRACE_TLS_OFFS_BUF_PTR) * 8) =
                            // data->buf_base_mem;
    BUF_PTR_INS(data->seg_base) =
        data->buf_base_ins; // *(ins_ref_t **) (void **)((byte *)(data->seg_base) +
                            // tls_offs + (INSTRACE_TLS_OFFS_BUF_PTR) * 8) =
                            // data->buf_base_ins;

    data->num_refs_mem = 0;
    data->num_refs_ins = 0;

    /* We're going to dump our data to a per-thread file.
     * On Windows we need an absolute path so we place it in
     * the same directory as our library. We could also pass
     * in a path as a client argument.
     */
    data->log =
        log_file_open(client_id, drcontext, NULL /* using client lib path */, "memtrace",
#ifndef WINDOWS
                      DR_FILE_CLOSE_ON_FORK |
#endif
                          DR_FILE_ALLOW_LARGE);
    data->logf = log_stream_from_file(data->log);
    fprintf(data->logf,
            "# Format: <data address>: <(r)ead/(w)rite/opcode>, <data size>\n");
    fprintf(data->logf, "# Format: <instr address>: <opcode>\n");

    // Don't trace at the beginning
    data->is_tracing = false;
    data->func_trigger_times = 0;
}

static void
event_thread_exit(void *drcontext)
{
    per_thread_t *data;
    memtrace(drcontext); /* dump any remaining buffer entries */
    data = drmgr_get_tls_field(drcontext, tls_idx);
    dr_mutex_lock(mutex);
    num_refs_mem += data->num_refs_mem;
    num_refs_target_mem += data->num_refs_target_mem;
    dr_mutex_unlock(mutex);

    instrace(drcontext); /* dump any remaining buffer entries */
    data = drmgr_get_tls_field(drcontext, tls_idx);
    dr_mutex_lock(mutex);
    num_refs_ins += data->num_refs_ins;
    num_refs_target_ins += data->num_refs_target_ins;
    dr_mutex_unlock(mutex);

    log_stream_close(data->logf); /* closes fd too */
    dr_raw_mem_free(data->buf_base_mem, MEM_BUF_SIZE_MEM_R);
    dr_raw_mem_free(data->buf_base_ins, MEM_BUF_SIZE_INS_R);
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

static void
event_exit(void)
{
    dr_log(NULL, DR_LOG_ALL, 1, "Client 'memtrace' num refs seen: " SZFMT "\n",
           num_refs_mem);
    dr_printf("\n######################################\n");
    dr_printf("######################################\n");
    dr_printf("### mem refs seen: " SZFMT "/" SZFMT "\n", num_refs_target_mem,
              num_refs_mem);
    dr_printf("### ins exec seen: " SZFMT "/" SZFMT "\n", num_refs_target_ins,
              num_refs_ins);
    if (!dr_raw_tls_cfree(tls_offs, MEMTRACE_TLS_COUNT))
        DR_ASSERT(false);

    if (!drmgr_unregister_tls_field(tls_idx) ||
        !drmgr_unregister_thread_init_event(event_thread_init) ||
        !drmgr_unregister_thread_exit_event(event_thread_exit) ||
#ifdef MAIN_TRACE_MEM
        !drmgr_unregister_bb_app2app_event(event_bb_app2app) ||
        !drmgr_unregister_bb_insertion_event(event_app_instruction) ||
#endif
#ifdef MAIN_TRACE_INS
        !drmgr_unregister_bb_insertion_event(event_app_instruction2) ||
#endif
        drreg_exit() != DRREG_SUCCESS)
        DR_ASSERT(false);

    dr_mutex_destroy(mutex);
    drutil_exit();
    drwrap_exit();
    drsym_exit();
    drmgr_exit();
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
	strcpy(TARGET_FUNC_NAME, argv[1]);
    /* We need 2 reg slots beyond drreg's eflags slots => 3 slots */
    drreg_options_t ops = { sizeof(ops), 3, false };
    dr_set_client_name("JackKuo 'trace_target_func_usage'", "https://jackkuo.org/");
    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS || !drutil_init() ||
        !drwrap_init())
        DR_ASSERT(false);

    /* register events */
    dr_register_exit_event(event_exit);
    if (
#ifdef MAIN_TRACE_MEM
        !drmgr_register_bb_app2app_event(event_bb_app2app, NULL) ||
        !drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL) ||
#endif
#ifdef MAIN_TRACE_INS
        !drmgr_register_bb_instrumentation_event(NULL, event_app_instruction2, NULL) ||
#endif
        !drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_thread_exit_event(event_thread_exit))
        DR_ASSERT(false);

    if (drsym_init(0) != DRSYM_SUCCESS) {
        dr_log(NULL, DR_LOG_ALL, 1, "WARNING: unable to initialize symbol translation\n");
    }
    get_app_name();
    wrapped = false;
    drmgr_register_module_load_event(module_load_event);
    client_id = id;

    mutex = dr_mutex_create();

    tls_idx = drmgr_register_tls_field();
    DR_ASSERT(tls_idx != -1);
    /* The TLS field provided by DR cannot be directly accessed from the code cache.
     * For better performance, we allocate raw TLS so that we can directly
     * access and update it with a single instruction.
     */
    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, MEMTRACE_TLS_COUNT, 0))
        DR_ASSERT(false);
    /* make it easy to tell, by looking at log file, which client executed */
    dr_log(NULL, DR_LOG_ALL, 1, "Client 'memtrace' initializing\n");
}

/* Get the application's name & its full path */
void
get_app_name()
{
    app_name = dr_get_application_name();
    dr_printf("[INFO] Program name: %s\n", app_name);
    dr_get_app_args(&app_args, 1);
    app_path = (char *)app_args.start;
    char ppp[50000];
    char *k = realpath(app_path, ppp);
    if (k != NULL)
        app_path = ppp;
    dr_printf("[INFO] Application path: %s\n", app_path);
}

