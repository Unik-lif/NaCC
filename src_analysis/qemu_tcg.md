## Qemu的TCG翻译机制

### TCG初始化
参考资料

https://wangzhou.github.io/qemu-tcg%E7%BF%BB%E8%AF%91%E6%89%A7%E8%A1%8C%E6%A0%B8%E5%BF%83%E9%80%BB%E8%BE%91%E5%88%86%E6%9E%90/


按照先前阅读的理解，在qemu中会先通过TCG将target指令转化成TCG IR，然后再把IR翻译成Host Machine能够模拟并且执行的机器码，不过具体这个流程怎么翻译，怎么初始化，我们会仔细地拆开来进行代码阅读和理解

首先，tcg_accel_class_init的初始化位置很早，是在qemu_create_machine的select_machine的环节就进去了，在这个时候CPU的线程都还没有启动起来
```
(gdb) bt
#0  tcg_accel_class_init (oc=0x555556a0a4c0, data=0x0) at ../accel/tcg/tcg-all.c:227
#1  0x0000555555e3dd37 in type_initialize (ti=0x55555688a170) at ../qom/object.c:423
#2  0x0000555555e3f700 in object_class_foreach_tramp (key=0x55555688a2f0, value=0x55555688a170, opaque=0x7fffffffdd10) at ../qom/object.c:1116
#3  0x00007ffff7b5c6b8 in g_hash_table_foreach () at /lib/x86_64-linux-gnu/libglib-2.0.so.0
#4  0x0000555555e3f7f0 in object_class_foreach (fn=0x555555e3f97b <object_class_get_list_tramp>, implements_type=0x55555620e361 "machine", include_abstract=false, opaque=0x7fffffffdd60)
    at ../qom/object.c:1138
#5  0x0000555555e3fa09 in object_class_get_list (implements_type=0x55555620e361 "machine", include_abstract=false) at ../qom/object.c:1195
#6  0x0000555555b4d5f8 in select_machine (qdict=0x555556891f30, errp=0x7fffffffddb0) at ../system/vl.c:1677
#7  0x0000555555b4e7b0 in qemu_create_machine (qdict=0x555556891f30) at ../system/vl.c:2117
#8  0x0000555555b52a8c in qemu_init (argc=10, argv=0x7fffffffe0e8) at ../system/vl.c:3678
#9  0x0000555555fd1fac in main (argc=10, argv=0x7fffffffe0e8) at ../system/main.c:47
```
之后，在我们对accelerators进行选择的时候，会调用tcg_accel_class_init这一步中设置好的诸多函数调用入口
- configure_accelerators
    - qemu_opts_foreach
        - do_configure_accelerator
            - accel_init_machine
                - tcg_init_machine: 这边似乎是对host机器做的感知
                    - tcg_init
                        - tcg_context_init
                            - tcg_target_init
                            - process_op_defs
                            - temp_tcgv_ptr
                        - tcg_region_init: page related
                    - tcg_prologue_init
                        - tcg_target_qemu_prologue

这边的do_configure_accelerator以及configure_accelerators，本质上是在Host机器中准备好了之后动态二进制翻译的环境，其实并没有真正开始serving

### TCG的运行
我们先前在梳理qemu整体流程的时候，提及过在sysbus_realize之后，我们会kick每一个模拟出来的cpu，跑起来多个线程，用来去做指令级别的serving。这些cpu的具体行为主要可以在mttcg_cpu_thread_fn函数中找到

我们接着主程序中的riscv_cpu_realize来做分析:

- riscv_cpu_realize
    - qemu_init_vcpu
        - mttcg_start_vcpu_thread
            - qemu_thread_create: mttcg_cpu_thread_fn

之后，子线程将会运行mttcg_cpu_thread_fn函数
- mttcg_cpu_thread_fn
    - tcg_cpu_exec
        - cpu_exec_start
        - cpu_exec: 外头的start和end，保证某个请求被一个cpu thread所独占，这里用了很不错的同步技巧，很值得学习
        - cpu_exec_end

- cpu_exec
    - cpu_handle_halt
        - cpu->cc->tcg_ops
        - tcg_ops->cpu_exec_halt(cpu)

核心函数情况
```C
int cpu_exec(CPUState *cpu)
{
    int ret;
    SyncClocks sc = { 0 };

    /* replay_interrupt may need current_cpu */
    current_cpu = cpu;

    if (cpu_handle_halt(cpu)) {
        return EXCP_HALTED;
    }

    RCU_READ_LOCK_GUARD();
    cpu_exec_enter(cpu);

    /*
     * Calculate difference between guest clock and host clock.
     * This delay includes the delay of the last cycle, so
     * what we have to do is sleep until it is 0. As for the
     * advance/delay we gain here, we try to fix it next time.
     */
    init_delay_params(&sc, cpu);

    ret = cpu_exec_setjmp(cpu, &sc);

    cpu_exec_exit(cpu);
    return ret;
}
```
似乎最核心的还是cpu_exec_setjmp函数，
```C
static int cpu_exec_setjmp(CPUState *cpu, SyncClocks *sc)
{
    /* Prepare setjmp context for exception handling. */
    // 此处设置了之后能够跳转回来的上下文信息
    if (unlikely(sigsetjmp(cpu->jmp_env, 0) != 0)) {
        cpu_exec_longjmp_cleanup(cpu);
    }

    return cpu_exec_loop(cpu, sc);
}

/* main execution loop */

// 尝试在这个execution loop中进行exception和interrupt的处理
static int __attribute__((noinline))
cpu_exec_loop(CPUState *cpu, SyncClocks *sc)
{
    int ret;

    /* if an exception is pending, we execute it here */
    // exception似乎是更加广义
    // interrupt是exception中的一种
    while (!cpu_handle_exception(cpu, &ret)) {
        TranslationBlock *last_tb = NULL;
        int tb_exit = 0;

        while (!cpu_handle_interrupt(cpu, &last_tb)) {
            TranslationBlock *tb;
            vaddr pc;
            uint64_t cs_base;
            uint32_t flags, cflags;
            // 来查看当前tb的状态
            // 写入到flags中以供之后使用
            cpu_get_tb_cpu_state(cpu_env(cpu), &pc, &cs_base, &flags);

            /*
             * When requested, use an exact setting for cflags for the next
             * execution.  This is used for icount, precise smc, and stop-
             * after-access watchpoints.  Since this request should never
             * have CF_INVALID set, -1 is a convenient invalid value that
             * does not require tcg headers for cpu_common_reset.
             */
            cflags = cpu->cflags_next_tb;
            if (cflags == -1) {
                cflags = curr_cflags(cpu);
            } else {
                cpu->cflags_next_tb = -1;
            }

            if (check_for_breakpoints(cpu, pc, &cflags)) {
                break;
            }
            // tb_lookup会根据一些状态来做tb的寻找，如果没有（一开始的情况），则会在之后tb_gen_code生成一下
            tb = tb_lookup(cpu, pc, cs_base, flags, cflags);
            if (tb == NULL) {
                CPUJumpCache *jc;
                uint32_t h;

                mmap_lock();
                tb = tb_gen_code(cpu, pc, cs_base, flags, cflags);
                mmap_unlock();

                /*
                 * We add the TB in the virtual pc hash table
                 * for the fast lookup
                 */
                h = tb_jmp_cache_hash_func(pc);
                jc = cpu->tb_jmp_cache;
                jc->array[h].pc = pc;
                qatomic_set(&jc->array[h].tb, tb);
            }

#ifndef CONFIG_USER_ONLY
            /*
             * We don't take care of direct jumps when address mapping
             * changes in system emulation.  So it's not safe to make a
             * direct jump to a TB spanning two pages because the mapping
             * for the second page can change.
             */
            if (tb_page_addr1(tb) != -1) {
                last_tb = NULL;
            }
#endif
            /* See if we can patch the calling TB. */
            if (last_tb) {
                tb_add_jump(last_tb, tb_exit, tb);
            }

            cpu_loop_exec_tb(cpu, tb, pc, &last_tb, &tb_exit);

            /* Try to align the host and virtual clocks
               if the guest is in advance */
            align_clocks(sc, cpu);
        }
    }
    return ret;
}

// 用于处理异常的程序
static inline bool cpu_handle_exception(CPUState *cpu, int *ret)
{
    if (cpu->exception_index < 0) {
#ifndef CONFIG_USER_ONLY
        if (replay_has_exception()
            && cpu->neg.icount_decr.u16.low + cpu->icount_extra == 0) {
            /* Execute just one insn to trigger exception pending in the log */
            cpu->cflags_next_tb = (curr_cflags(cpu) & ~CF_USE_ICOUNT)
                | CF_NOIRQ | 1;
        }
#endif
        return false;
    }

    if (cpu->exception_index >= EXCP_INTERRUPT) {
        /* exit request from the cpu execution loop */
        *ret = cpu->exception_index;
        if (*ret == EXCP_DEBUG) {
            cpu_handle_debug_exception(cpu);
        }
        cpu->exception_index = -1;
        return true;
    }

#if defined(CONFIG_USER_ONLY)
    /*
     * If user mode only, we simulate a fake exception which will be
     * handled outside the cpu execution loop.
     */
#if defined(TARGET_I386)
    const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;
    tcg_ops->fake_user_interrupt(cpu);
#endif /* TARGET_I386 */
    *ret = cpu->exception_index;
    cpu->exception_index = -1;
    return true;
#else
    if (replay_exception()) {
        const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;

        bql_lock();
        tcg_ops->do_interrupt(cpu);
        bql_unlock();
        cpu->exception_index = -1;

        if (unlikely(cpu->singlestep_enabled)) {
            /*
             * After processing the exception, ensure an EXCP_DEBUG is
             * raised when single-stepping so that GDB doesn't miss the
             * next instruction.
             */
            *ret = EXCP_DEBUG;
            cpu_handle_debug_exception(cpu);
            return true;
        }
    } else if (!replay_has_interrupt()) {
        /* give a chance to iothread in replay mode */
        *ret = EXCP_INTERRUPT;
        return true;
    }
#endif

    return false;
}

static inline bool cpu_handle_interrupt(CPUState *cpu,
                                        TranslationBlock **last_tb)
{
    /*
     * If we have requested custom cflags with CF_NOIRQ we should
     * skip checking here. Any pending interrupts will get picked up
     * by the next TB we execute under normal cflags.
     */
    if (cpu->cflags_next_tb != -1 && cpu->cflags_next_tb & CF_NOIRQ) {
        return false;
    }

    /* Clear the interrupt flag now since we're processing
     * cpu->interrupt_request and cpu->exit_request.
     * Ensure zeroing happens before reading cpu->exit_request or
     * cpu->interrupt_request (see also smp_wmb in cpu_exit())
     */
    qatomic_set_mb(&cpu->neg.icount_decr.u16.high, 0);

    if (unlikely(qatomic_read(&cpu->interrupt_request))) {
        int interrupt_request;
        bql_lock();
        interrupt_request = cpu->interrupt_request;
        if (unlikely(cpu->singlestep_enabled & SSTEP_NOIRQ)) {
            /* Mask out external interrupts for this step. */
            interrupt_request &= ~CPU_INTERRUPT_SSTEP_MASK;
        }
        if (interrupt_request & CPU_INTERRUPT_DEBUG) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_DEBUG;
            cpu->exception_index = EXCP_DEBUG;
            bql_unlock();
            return true;
        }
#if !defined(CONFIG_USER_ONLY)
        if (replay_mode == REPLAY_MODE_PLAY && !replay_has_interrupt()) {
            /* Do nothing */
        } else if (interrupt_request & CPU_INTERRUPT_HALT) {
            replay_interrupt();
            cpu->interrupt_request &= ~CPU_INTERRUPT_HALT;
            cpu->halted = 1;
            cpu->exception_index = EXCP_HLT;
            bql_unlock();
            return true;
        }
#if defined(TARGET_I386)
        else if (interrupt_request & CPU_INTERRUPT_INIT) {
            X86CPU *x86_cpu = X86_CPU(cpu);
            CPUArchState *env = &x86_cpu->env;
            replay_interrupt();
            cpu_svm_check_intercept_param(env, SVM_EXIT_INIT, 0, 0);
            do_cpu_init(x86_cpu);
            cpu->exception_index = EXCP_HALTED;
            bql_unlock();
            return true;
        }
#else
        else if (interrupt_request & CPU_INTERRUPT_RESET) {
            replay_interrupt();
            cpu_reset(cpu);
            bql_unlock();
            return true;
        }
#endif /* !TARGET_I386 */
        /* The target hook has 3 exit conditions:
           False when the interrupt isn't processed,
           True when it is, and we should restart on a new TB,
           and via longjmp via cpu_loop_exit.  */
        else {
            const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;

            if (tcg_ops->cpu_exec_interrupt(cpu, interrupt_request)) {
                if (!tcg_ops->need_replay_interrupt ||
                    tcg_ops->need_replay_interrupt(interrupt_request)) {
                    replay_interrupt();
                }
                /*
                 * After processing the interrupt, ensure an EXCP_DEBUG is
                 * raised when single-stepping so that GDB doesn't miss the
                 * next instruction.
                 */
                if (unlikely(cpu->singlestep_enabled)) {
                    cpu->exception_index = EXCP_DEBUG;
                    bql_unlock();
                    return true;
                }
                cpu->exception_index = -1;
                *last_tb = NULL;
            }
            /* The target hook may have updated the 'cpu->interrupt_request';
             * reload the 'interrupt_request' value */
            interrupt_request = cpu->interrupt_request;
        }
#endif /* !CONFIG_USER_ONLY */
        if (interrupt_request & CPU_INTERRUPT_EXITTB) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_EXITTB;
            /* ensure that no TB jump will be modified as
               the program flow was changed */
            *last_tb = NULL;
        }

        /* If we exit via cpu_loop_exit/longjmp it is reset in cpu_exec */
        bql_unlock();
    }

    /* Finally, check if we need to exit to the main loop.  */
    if (unlikely(qatomic_read(&cpu->exit_request)) || icount_exit_request(cpu)) {
        qatomic_set(&cpu->exit_request, 0);
        if (cpu->exception_index == -1) {
            cpu->exception_index = EXCP_INTERRUPT;
        }
        return true;
    }

    return false;
}
```
另外一重要节点：为现有的代码生成一个tb，tb中有已经通过动态二进制翻译技术得到的新指令
```C
/*
 * Isolate the portion of code gen which can setjmp/longjmp.
 * Return the size of the generated code, or negative on error.
 */
static int setjmp_gen_code(CPUArchState *env, TranslationBlock *tb,
                           vaddr pc, void *host_pc,
                           int *max_insns, int64_t *ti)
{
    int ret = sigsetjmp(tcg_ctx->jmp_trans, 0);
    if (unlikely(ret != 0)) {
        return ret;
    }

    tcg_func_start(tcg_ctx);

    tcg_ctx->cpu = env_cpu(env);
    gen_intermediate_code(env_cpu(env), tb, max_insns, pc, host_pc);
    assert(tb->size != 0);
    tcg_ctx->cpu = NULL;
    *max_insns = tb->icount;

    return tcg_gen_code(tcg_ctx, tb, pc);
}
```
这边做翻译，终于看到了！
```
(gdb) s
decode_insn32 (ctx=0x7ffff57ff260, insn=42108435) at libqemu-riscv64-softmmu.a.p/decode-insn32.c.inc:2058
2058    {
(gdb) n
2091        switch (insn & 0x0000007f) {
(gdb)
2489            switch ((insn >> 12) & 0x7) {
(gdb)
2493                decode_insn32_extract_i(ctx, &u.f_i, insn);
(gdb)
2494                if (trans_addi(ctx, &u.f_i)) return true;
(gdb)
7578    }
(gdb)
```

### 附录
新学的一些gdb调试技巧
```
ptype查看结构体定义

```