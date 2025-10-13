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

vma的设置
- exec_binprm
    - search_binary_handler
        - load_elf_binary
            - arch_setup_additional_pages
                - 
                - __setup_additional_pages
                    - _install_special_mapping
                        - __install_special_mapping
                            - insert_vm_struct
                                - vma_link