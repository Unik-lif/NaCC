## qemu对于cpu和其他组建的初始化
找了老半天似乎没有找到程序的入口，感觉这件事情首先tcg有关，昨天我们注意到在sysbus_realize之后有多个线程被创建出来了，现在我们注意到了这一点确实是在tcg的初始化位置，这在machine_init之前
```C
// (gdb) bt
// #0  tcg_accel_ops_init (ops=0x555556a10550) at ../accel/tcg/tcg-accel-ops.c:201
// #1  0x0000555555bd194b in accel_system_init_ops_interfaces (ac=0x555556a0a4c0) at ../accel/accel-system.c:88
// #2  0x0000555555e01aae in accel_init_interfaces (ac=0x555556a0a4c0) at ../accel/accel-target.c:107
// #3  0x0000555555915e31 in machine_run_board_init (machine=0x555556a95b50, mem_path=0x0, errp=0x7fffffffd9a0) at ../hw/core/machine.c:1629
// #4  0x0000555555b4fecc in qemu_init_board () at ../system/vl.c:2632
// #5  0x0000555555b50230 in qmp_x_exit_preconfig (errp=0x5555567f38c0 <error_fatal>) at ../system/vl.c:2718
// #6  0x0000555555b52c1f in qemu_init (argc=10, argv=0x7fffffffdcd8) at ../system/vl.c:3753
// #7  0x0000555555fd1fac in main (argc=10, argv=0x7fffffffdcd8) at ../system/main.c:47

static void tcg_accel_ops_init(AccelOpsClass *ops)
{
    if (qemu_tcg_mttcg_enabled()) {
        ops->create_vcpu_thread = mttcg_start_vcpu_thread;
        ops->kick_vcpu_thread = mttcg_kick_vcpu_thread;
        ops->handle_interrupt = tcg_handle_interrupt;
    } else {
        ops->create_vcpu_thread = rr_start_vcpu_thread;
        ops->kick_vcpu_thread = rr_kick_vcpu_thread;

        if (icount_enabled()) {
            ops->handle_interrupt = icount_handle_interrupt;
            ops->get_virtual_clock = icount_get;
            ops->get_elapsed_ticks = icount_get;
        } else {
            ops->handle_interrupt = tcg_handle_interrupt;
        }
    }

    ops->cpu_reset_hold = tcg_cpu_reset_hold;
    ops->supports_guest_debug = tcg_supports_guest_debug;
    ops->insert_breakpoint = tcg_insert_breakpoint;
    ops->remove_breakpoint = tcg_remove_breakpoint;
    ops->remove_all_breakpoints = tcg_remove_all_breakpoints;
}
```

我们直接看看函数调用栈情况
```
(gdb) bt
#0  riscv_cpu_realize (dev=0x555556ab1df0, errp=0x7fffffffd3d0) at ../target/riscv/cpu.c:1163
#1  0x0000555555e37daf in device_set_realized (obj=0x555556ab1df0, value=true, errp=0x7fffffffd690) at ../hw/core/qdev.c:495
#2  0x0000555555e429b0 in property_set_bool (obj=0x555556ab1df0, v=0x555556ad6320, name=0x55555627b849 "realized", opaque=0x555556898eb0, errp=0x7fffffffd690) at ../qom/object.c:2348
#3  0x0000555555e40574 in object_property_set (obj=0x555556ab1df0, name=0x55555627b849 "realized", v=0x555556ad6320, errp=0x7fffffffd690) at ../qom/object.c:1455
#4  0x0000555555e4517f in object_property_set_qobject (obj=0x555556ab1df0, name=0x55555627b849 "realized", value=0x555556ad61b0, errp=0x7fffffffd690) at ../qom/qom-qobject.c:28
#5  0x0000555555e4091d in object_property_set_bool (obj=0x555556ab1df0, name=0x55555627b849 "realized", value=true, errp=0x7fffffffd690) at ../qom/object.c:1525
#6  0x0000555555e374c9 in qdev_realize (dev=0x555556ab1df0, bus=0x0, errp=0x7fffffffd690) at ../hw/core/qdev.c:276
#7  0x0000555555c227c7 in riscv_hart_realize (s=0x555556a95ce8, idx=0, cpu_type=0x555556ab1af0 "rv64-riscv-cpu", errp=0x7fffffffd690) at ../hw/riscv/riscv_hart.c:52
#8  0x0000555555c2284a in riscv_harts_realize (dev=0x555556a95ce8, errp=0x7fffffffd690) at ../hw/riscv/riscv_hart.c:63
#9  0x0000555555e37daf in device_set_realized (obj=0x555556a95ce8, value=true, errp=0x7fffffffd7a0) at ../hw/core/qdev.c:495
#10 0x0000555555e429b0 in property_set_bool (obj=0x555556a95ce8, v=0x555556ab1cf0, name=0x55555627b849 "realized", opaque=0x555556898eb0, errp=0x7fffffffd7a0) at ../qom/object.c:2348
#11 0x0000555555e40574 in object_property_set (obj=0x555556a95ce8, name=0x55555627b849 "realized", v=0x555556ab1cf0, errp=0x7fffffffd7a0) at ../qom/object.c:1455
#12 0x0000555555e4517f in object_property_set_qobject (obj=0x555556a95ce8, name=0x55555627b849 "realized", value=0x555556ab1710, errp=0x5555567f38c0 <error_fatal>) at ../qom/qom-qobject.c:28
#13 0x0000555555e4091d in object_property_set_bool (obj=0x555556a95ce8, name=0x55555627b849 "realized", value=true, errp=0x5555567f38c0 <error_fatal>) at ../qom/object.c:1525
#14 0x0000555555e374c9 in qdev_realize (dev=0x555556a95ce8, bus=0x555556a9db50, errp=0x5555567f38c0 <error_fatal>) at ../hw/core/qdev.c:276
#15 0x000055555591da29 in sysbus_realize (dev=0x555556a95ce8, errp=0x5555567f38c0 <error_fatal>) at ../hw/core/sysbus.c:246
#16 0x0000555555c28739 in virt_machine_init (machine=0x555556a95b50) at ../hw/riscv/virt.c:1504
#17 0x0000555555915e45 in machine_run_board_init (machine=0x555556a95b50, mem_path=0x0, errp=0x7fffffffd9a0) at ../hw/core/machine.c:1630
#18 0x0000555555b4fecc in qemu_init_board () at ../system/vl.c:2632
#19 0x0000555555b50230 in qmp_x_exit_preconfig (errp=0x5555567f38c0 <error_fatal>) at ../system/vl.c:2718
#20 0x0000555555b52c1f in qemu_init (argc=10, argv=0x7fffffffdcd8) at ../system/vl.c:3753
#21 0x0000555555fd1fac in main (argc=10, argv=0x7fffffffdcd8) at ../system/main.c:47
```
原来入口还是在qmp_x_exit_prefconfig中的qemu_init_board这边，在sysbus_realize函数之下，可以理解成利用总线去感知CPU做下面的事情。你要是说还按着昨天的那个方法来找，可能真的老费力气了。

接着昨天的节奏走

实例化的效果
```
static void riscv_harts_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    device_class_set_props(dc, riscv_harts_props);
    dc->realize = riscv_harts_realize;
}
```

函数调用栈:
- machine->init: virt_machine_init riscv
    - sysbus_realize
        - qdev_realize: Initialize the device in the bus
            - object_property_set_bool
                - object_property_set_qobject
                    - object_property_set
                        - prop->set: property_set_bool
                            - prop->set: device_set_realized
                                - dc->realize: riscv_harts_realize
                                    - riscv_hart_realize
                                        - qdev_realize
                                            - object_property_set_bool
                                                - object_property_set_qobject
                                                    - object_property_set
                                                        - prop->set: property_set_bool
                                                            - prop->set: device_set_realized
                                                                - dc->realize: riscv_cpu_realize

之后初始化疑似走到了qemu_init_vcpu，然后对vcpu的初始化会走到mttcg_start_vcpu_thread这个函数中，这样就和tcg_accel_ops_init接续在了一起，不过这似乎已经初始化完了，我们之后找到了tcg去感知cpu的真实入口，似乎是在riscv_tcg_cpu_realize函数中

含有*号的，我们会重点看
- riscv_cpu_realize
    - cpu_exec_realizefn
        - accel_cpu_common_realize
            - *riscv_tcg_cpu_realize
                - riscv_cpu_tcg_compatible
                    - object_dynamic_cast
                        - type_get_by_name_noload: host-riscv-cpu
                            - type_table_lookup: host-riscv-cpu 找到了我们要的类型
                - tcg_cflags_set
                - riscv_timer_init
                - riscv_pmu_init
                - riscv_has_ext
        - tcg_exec_realizefn
            - *riscv_translate_init

                        
    - qemu_init_vcpu
        - mttcg_start_vcpu_thread
            - qemu_thread_create
                - qemu_thread_create - new thread: mttcg_cpu_thread_fn

最关键的函数起始就是riscv_tcg_cpu_realize
```C
static bool riscv_tcg_cpu_realize(CPUState *cs, Error **errp)
{
    RISCVCPU *cpu = RISCV_CPU(cs);

    if (!riscv_cpu_tcg_compatible(cpu)) {
        g_autofree char *name = riscv_cpu_get_name(cpu);
        error_setg(errp, "'%s' CPU is not compatible with TCG acceleration",
                   name);
        return false;
    }

#ifndef CONFIG_USER_ONLY
    // 此处的env能够看到完整的cpu上下文信息
    CPURISCVState *env = &cpu->env;
    Error *local_err = NULL;

    tcg_cflags_set(CPU(cs), CF_PCREL);

    if (cpu->cfg.ext_sstc) {
        // 在env中设置了stimer, vstimer, stimecmp, vstimecmp等信息
        riscv_timer_init(cpu);
    }

    if (cpu->cfg.pmu_mask) {
        // pmu是riscv的性能监控单元，统计硬件事件，做这个初始化
        riscv_pmu_init(cpu, &local_err);
        if (local_err != NULL) {
            error_propagate(errp, local_err);
            return false;
        }

        if (cpu->cfg.ext_sscofpmf) {
            cpu->pmu_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                          riscv_pmu_timer_cb, cpu);
        }
    }

    /* With H-Ext, VSSIP, VSTIP, VSEIP and SGEIP are hardwired to one. */
    // 对mideleg寄存器做一个写
    if (riscv_has_ext(env, RVH)) {
        env->mideleg = MIP_VSSIP | MIP_VSTIP | MIP_VSEIP | MIP_SGEIP;
    }
#endif

    return true;
}
```
此处确实完成了cpu的初始化，以及env的设置，这一步很关键！

然而，程序似乎还是没有跑起来，我们可能还是得往下看！

我们看到了tcg_exec_realizefn这边，会进入到riscv_translate_init，追溯来看，这边涉及tcg等很多东西的适配！
```C
static const TCGCPUOps riscv_tcg_ops = {
    .initialize = riscv_translate_init,
    .synchronize_from_tb = riscv_cpu_synchronize_from_tb,
    .restore_state_to_opc = riscv_restore_state_to_opc,

#ifndef CONFIG_USER_ONLY
    .tlb_fill = riscv_cpu_tlb_fill,
    .cpu_exec_interrupt = riscv_cpu_exec_interrupt,
    .cpu_exec_halt = riscv_cpu_has_work,
    .do_interrupt = riscv_cpu_do_interrupt,
    .do_transaction_failed = riscv_cpu_do_transaction_failed,
    .do_unaligned_access = riscv_cpu_do_unaligned_access,
    .debug_excp_handler = riscv_cpu_debug_excp_handler,
    .debug_check_breakpoint = riscv_cpu_debug_check_breakpoint,
    .debug_check_watchpoint = riscv_cpu_debug_check_watchpoint,
#endif /* !CONFIG_USER_ONLY */
};
```
在一些基本的程序进行之后，qemu系统会调用这些riscv所特别对应的函数，来模拟完成系统的功能！

在这边我们可以看到riscv_translate_init，对很多寄存器做了初始的赋值，之后就等待程序跑起来啦！
```C
void riscv_translate_init(void)
{
    int i;

    /*
     * cpu_gpr[0] is a placeholder for the zero register. Do not use it.
     * Use the gen_set_gpr and get_gpr helper functions when accessing regs,
     * unless you specifically block reads/writes to reg 0.
     */
    cpu_gpr[0] = NULL;
    cpu_gprh[0] = NULL;

    for (i = 1; i < 32; i++) {
        cpu_gpr[i] = tcg_global_mem_new(tcg_env,
            offsetof(CPURISCVState, gpr[i]), riscv_int_regnames[i]);
        cpu_gprh[i] = tcg_global_mem_new(tcg_env,
            offsetof(CPURISCVState, gprh[i]), riscv_int_regnamesh[i]);
    }

    for (i = 0; i < 32; i++) {
        cpu_fpr[i] = tcg_global_mem_new_i64(tcg_env,
            offsetof(CPURISCVState, fpr[i]), riscv_fpr_regnames[i]);
    }

    cpu_pc = tcg_global_mem_new(tcg_env, offsetof(CPURISCVState, pc), "pc");
    cpu_vl = tcg_global_mem_new(tcg_env, offsetof(CPURISCVState, vl), "vl");
    cpu_vstart = tcg_global_mem_new(tcg_env, offsetof(CPURISCVState, vstart),
                            "vstart");
    load_res = tcg_global_mem_new(tcg_env, offsetof(CPURISCVState, load_res),
                             "load_res");
    load_val = tcg_global_mem_new(tcg_env, offsetof(CPURISCVState, load_val),
                             "load_val");
    /* Assign PM CSRs to tcg globals */
    pm_mask = tcg_global_mem_new(tcg_env, offsetof(CPURISCVState, cur_pmmask),
                                 "pmmask");
    pm_base = tcg_global_mem_new(tcg_env, offsetof(CPURISCVState, cur_pmbase),
                                 "pmbase");
}
```
然而我看得不是很懂，我们的下一步也就昭然若揭了！我们通过qemu_intro和qemu_cpu两篇文章，已经搞清楚了qemu初始化在cpu上的基本流程，以及使用的基本模块和工具！为了让程序能够真正跑起来，我们需要进入一个陌生的领域，动态二进制翻译！也就是qemu中最有意思的tcg模块啦！

希望探险顺利！