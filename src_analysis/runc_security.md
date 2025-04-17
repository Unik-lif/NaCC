这边记录yiying zhang推荐的understanding and hardening linux containers这一本书

## Chapter 3: Namespaces
主要似乎涉及两个系统调用的使用
- setns
- unshare
用于加入某一个或者离开某一个namespaces

对应的不同类型的namespace: 目前似乎有八个了
- mount namespace: 最早引入，文件系统相关
- IPC namespace: 在共享内存上做的，攻击内核的共享内存
- UTS namespace: Different hostname and domain
- PID namespace: by protecting from cross-application attacks, information leaks, malicious use of ptrace and other such potential weaknesses
- Network namespace
- User namespace

> https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-2/

简单理解就是在某个namespace下，有一些特定的权限限制

不过看起来比较像一个独立作用域，控制一个进程能够看到什么

```
   The namespaces API
       As well as various /proc files described below, the namespaces API
       includes the following system calls:

       clone(2)
              The clone(2) system call creates a new process.  If the
              flags argument of the call specifies one or more of the
              CLONE_NEW* flags listed above, then new namespaces are
              created for each flag, and the child process is made a
              member of those namespaces.  (This system call also
              implements a number of features unrelated to namespaces.)

       setns(2)
              The setns(2) system call allows the calling process to join
              an existing namespace.  The namespace to join is specified
              via a file descriptor that refers to one of the
              /proc/pid/ns files described below.

       unshare(2)
              The unshare(2) system call moves the calling process to a
              new namespace.  If the flags argument of the call specifies
              one or more of the CLONE_NEW* flags listed above, then new
              namespaces are created for each flag, and the calling
              process is made a member of those namespaces.  (This system
              call also implements a number of features unrelated to
              namespaces.)

       ioctl(2)
              Various ioctl(2) operations can be used to discover
              information about namespaces.  These operations are
              described in ioctl_nsfs(2).

       Creation of new namespaces using clone(2) and unshare(2) in most
       cases requires the CAP_SYS_ADMIN capability, since, in the new
       namespace, the creator will have the power to change global
       resources that are visible to other processes that are
       subsequently created in, or join the namespace.  User namespaces
       are the exception: since Linux 3.8, no privilege is required to
       create a user namespace.
```
似乎要控制这一部分系统调用的使用。

namespace机制允许一个进程有多个处于的namespace，且在不同的namespace下，我们允许其对应的PID是不同的。
## Chapter 4: cgroups
感觉更加贴近于资源限制

二者之间的关联：

> https://www.andrew.cmu.edu/course/14-712-s20/applications/ln/Namespaces_Cgroups_Conatiners.pdf

一个负责开作用域，另一个用于做资源限制

https://www.toptal.com/linux/separation-anxiety-isolating-your-system-with-linux-namespaces