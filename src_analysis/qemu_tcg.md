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
### 附录
新学的一些gdb调试技巧
```
ptype查看结构体定义

```