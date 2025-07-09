## Qemu代码初阅读
确实没有看过qemu的代码，感觉会很有意思，尝试快速找到主线

我们首先尝试学习qemu internal，再尝试学习martins3中的qemu阅读代码的方法

### Qemu事件循环机制
本质上是因为它有很多异步事件需要处理，不能通过CPU直接计算得到，而是需要和Host系统异步着交互起来，这需要一个统一的事件循环去做
- 轮询和等待
- 使用回调函数来尝试处理这些事件

我很喜欢chatgpt的总结：

QEMU 初始化：
- 创建 aio_context（事件上下文）
- 初始化时钟/定时器机制
- 设置 bottom-half（延迟任务回调）
- 准备要监听的 fd 列表

每轮事件循环：
- 调用 aio_poll() → 封装 glib 的 g_main_context_iteration()
- 检查所有 fd、定时器，是否准备就绪
- 就绪就调用之前注册的回调（比如网络包处理函数、定时器函数等）

回调执行后，主线程恢复模拟 CPU 执行（QEMU 就像跑在 IO 驱动 + CPU tick 的沙漏中）

如果有个串口设备要加入，就通过qemu_set_fd_handler把fd写到aio_context中，只要fd上有Host输入，glib事件将会发现这个fd可读，于是就去触发回调函数，进一步接受数据，写入buffer，guest这边进一步产生中断

### qemu的初始化
先是很大一部分参数的初始化和选取，之后我们进入到vl.c中的后半部分

- qemu_init_main_loop: 形成事件驱动型状态机，以和device等之后进行交互
    - init_clocks
    - qemu_signal_init
    - aio_context_new: 生成qemu_aio_context
    - iohandler_get_g_source: 生成io-handler
- qemu_create_machine: 选择合适的机器类型
    - cpu_exec_init_all
        - finalize_target_page_bits: 有一些小架构如Arm可能用1KB的小页
        - io_mem_init:
        - memory_map_init: 对下面的这俩空间进行初始化
            - address_space_memory
            - address_space_io
- qemu_create_default_devices

到这边就已经是PHASE_MACHINE_CREATED状态了

- configure_accelerators: 选择可能可以使用的加速方式，包括kvm，tcg等，由于riscv指令集我们需要动态翻译，因此选取tcg来做

至此是PHASE_ACCEL_CREATED

- MACHINE_GET_CLASS
- qemu_create_late_backends: 驱动与相关设备
    - net_init_clients
    - foreach_device_config
    - qemu_semihosting_chardev_init

PHASE_LATE_BACKENDS_CREATED

- migration_object_init 和迁移相关，里头一堆锁的初始化
- qmp_x_exit_preconfig 机器的初始化和创造，抽象来到主板曾
    - qemu_init_board
        - qemu_plugin_load_list
        - machine_run_board_init: 进入MACHINE_PHASE_INITIALIZED
            - numa_complete_configuration
            - machine_consume_memdev
                - host_memory_backend_get_memory
                - host_memory_backend_set_mapped
            - accel_init_interfaces: 此处有tcg的init，如下所示会进入到tcg_accel_ops_init的函数，我们按下不表      
```
(gdb) n
88              ops->ops_init(ops);
(gdb) s
tcg_accel_ops_init (ops=0x555556a10550) at ../accel/tcg/tcg-accel-ops.c:201
201         if (qemu_tcg_mttcg_enabled()) {
(gdb) 
```
            之后结束后，会进入到PHASE_MACHINE_INITIALIZED
            - machine->init: 也是一个非常重要的函数
                - get_system_memory
                - sysbus_realize: 总线上对于一些设备可达性的验证
                - riscv_aclint_swi_create
                - riscv_aclint_mtimer_create: cpu 基本配置，包括freq，hartid，num-harts等信息
                - memory_region_add_subregion: DRAM，这一部分涉及内存区域的初始化
                - memory_region_init_rom
                - memory_region_add_subregion: MROM
            PHASE_MACHINE_INITIALIZED
    - qemu_create_cli_devices
        - rom related
    - qemu_machine_creation_done
        - qdev_machine_creation_done
        - PHASE_MACHINE_READY
- accel_setup_post
- os_setup_post
- resume_mux_open


大体做了这么多事情之后，我们终于离开了qemu init，现在进入qemu_main

qemu_default_main
- qemu_main_loop: 下面的流程非常经典
    - main_loop_should_exit
        - qemu_debug/suspend/shutdown/reset/wakeup/powerdown/vmstop/_requested
        - pause_all_vcpus/resume_all_vcpus: are involved
    - main_loop_wait

main_loop_wait有一个很精彩的注释
```
If @nonblocking is true, poll for events, otherwise suspend until
one actually occurs. The main loop usually consists of a loop that
repeatedly calls main_loop_wait(false).

Main loop services include file descriptor callbacks, bottom halves
and timers (defined in qemu/timer.h). Bottom halves are similar to timers
that execute immediately, but have a lower overhead and scheduling them
is wait-free, thread-safe and signal-safe.

It is sometimes useful to put a whole program in a coroutine. In this
case, the coroutine actually should be started from within the main loop,
so that the main loop can run whenever the coroutine yields. To do this,
you can use a bottom half to enter the coroutine as soon as the main loop
starts:
```
看到这里感觉是真的懂了，但是，qemu总体还是使用高度抽象的方式来搭建整个系统，我们到目前似乎还没有特别深入到riscv本身cpu上的一些设置。这个内容很有可能是在machine->init这边展示，我们需要更加仔细地对此进行深入