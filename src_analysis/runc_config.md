## runC权限配置
runC最终调用的是libcontainer，这里涉及许多不同的安全机制配置

并不困难，我们主要列举如下
- namespace
- cgroups
- capability
- seccomp

但是由于OS-Level隔离机制的锁碎性，这些东西很难用一个general的框架放在一起讨论研究

我们后续会尝试仔细考虑这件事情怎么得到妥善的解决