## linux对于elf和vma的使用

### ELF的装载过程
在toy os中elf的装载过程我很熟悉了，但是在linux这种现代操作系统中，其实还是有一点不一样的

linux会在exec系统调用发生的时候解读elf，但是和toy os不一样，现代操作系统的elf一般是含有动态解释器的，需要动态链接过来，为此，ELF文件中会有PT_INTERP字段，这个在很多toy os面对的静态链接情况没有，解释器字段将会帮助找到解释器，进一步

- load_elf_binary
    - (minor checks)
    - load_elf_phdrs
    - interp_elf_ex = kmalloc(sizeof(*interp_elf_ex), GFP_KERNEL)

PT_INTERP应该只有一个字段，因此搞定之后马上就break退出，这边遍历是迅速找到它这个字段

之后，检查PT_GNU_STACK以及arch本身架构特定的程序头，为栈区域和架构特定的区域准备好对应的权限，用来指导后续VMA区域的权限布置情况
### VMA
在load_elf_binary之后，出现了begin_new_exec函数


vma的设置
- exec_binprm
    - search_binary_handler
        - load_elf_binary
            - begin_new_exec
                - mmput
                    - _mmput
                        - exit_mmap: 清空了旧的进程，但是新的进程只是放了一个占位，真正的VMA还没有放进去
                            - unmap_vmas: 取消映射，把物理页面返回给页面的分配器
                                - zap_pte_range: 会清空pte，但是其他页表页不动，把可以被释放的物理页放到待释放位置
                            - free_pgtables: 先获取vma所对应的页表区域，然后再释放页表，主要处理
                            - remove_vma: 释放掉VMA结构，减少vm_file的引用计数，释放内存策略相关资源
                - begin_new_exec: 建立临时栈VMA
                - setup_arg_pages: 建立正式栈VMA，用来存放参数
            - for(i = 0, elf_ppnt = elf_phdata; i < elf_ex->e_phnum; i++, elf_ppnt++)
                - first_pt_load确认是静态链接模式还是动态链接模式
                - 完成权限配置和VMA区域对齐之后，使用elf_load
                    - elf_map
                        - vm_mmap
                            - vm_mmap_pgoff
                                - do_mmap
                                    - mmap_region
                                        - __map_region
                                            - vma_set_range
            - load_elf_interp
            - arch_setup_additional_pages
                - __setup_additional_pages
                    - _install_special_mapping
                        - __install_special_mapping
                            - insert_vm_struct
                                - vma_link

因此我们可以得出结论
```
1. begin_new_exec()           // 清理旧进程的所有VMA
   └─ exec_mmap()            // 切换到新的空白mm_struct

2. setup_arg_pages()         // 创建栈VMA
   └─ 将临时栈VMA转换为正式栈VMA

3. 主循环: elf_load()        // 创建程序段VMA
   ├─ 代码段VMA (.text)
   ├─ 数据段VMA (.data) 
   └─ BSS段VMA (.bss)

4. load_elf_interp()         // 创建动态链接器VMA (如果有)
   ├─ ld.so代码段VMA
   ├─ ld.so数据段VMA
   └─ ld.so BSS段VMA

5. ARCH_SETUP_ADDITIONAL_PAGES // 创建架构特定VMA
   └─ VDSO VMA (x86-64)

6. create_elf_tables()       // 完善栈VMA内容
   └─ 在栈中写入参数、环境变量、辅助向量

7. 特殊VMA (可选)
   └─ 页面0映射 (兼容性)

0xFFFFFFFFFFFFFFFF ← 内核空间
┌─────────────────┐
│     [内核]      │
├─────────────────┤ 0x00007FFFFFFFFFFF ← 用户空间上限
│     栈VMA       │ ← setup_arg_pages()创建
│   (可增长)      │   包含参数、环境变量、辅助向量
├─────────────────┤ 
│                 │
│     [GAP]       │ ← 内存映射区域 (mmap)
│                 │
├─────────────────┤ 0x00007FFFF7000000 (典型)
│   VDSO VMA      │ ← ARCH_SETUP_ADDITIONAL_PAGES()
├─────────────────┤
│ 动态链接器VMA   │ ← load_elf_interp()创建
│   ld.so段       │   (.text, .data, .bss)
├─────────────────┤ 0x0000555555560000 (典型)
│     堆VMA       │ ← 将来通过brk()系统调用创建
│   (可增长)      │
├─────────────────┤ current->mm->brk
│   BSS段VMA      │ ← elf_load()创建 (匿名映射)
├─────────────────┤
│   数据段VMA     │ ← elf_load()创建 (文件映射)
├─────────────────┤ 
│   代码段VMA     │ ← elf_load()创建 (文件映射)
├─────────────────┤ 0x0000555555554000 (典型PIE程序)
│   页面0VMA      │ ← 兼容性映射 (可选)
└─────────────────┘ 0x0000000000000000
```
此外，并非所有的页面都是会延迟分配的，比如VDSO，我们之后针对这个区域再做特殊查看，用来观察包括页表页等metadata数据的建立

在load_elf_binary函数中其实涉及多个系统调用handler的使用，因此确实有充分学习研究的必要