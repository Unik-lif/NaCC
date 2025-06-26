## runc init流程分析
### nsenter背景知识
在runc create的时候，以及runc init的时候，有一部分代码有明显中断的地方，我们仔细观察，发现事情和C部分的nsenter代码有关系

在go runtime中，goroutine本身是含有多个线程的进程，它似乎是没有能力去调用setns这个接口来创建namespace

这里有一个较好的解释：https://stackoverflow.com/questions/42696589/libcontainer-runc-and-nsenter-bootstrap

本质上似乎是GNU本身添加的性质，就像是黑魔法一样，允许标上某些标志的代码能够在main之前运行

constructor (priority) and destructor (priority)

> The constructor attribute causes the function to be called automatically before execution enters main (). Similarly, the destructor attribute causes the function to be called automatically after main () completes or exit () is called. Functions with these attributes are useful for initializing data that is used implicitly during the execution of the program.
You may provide an optional integer priority to control the order in which constructor and destructor functions are run. A constructor with a smaller priority number runs before a constructor with a larger priority number; the opposite relationship holds for destructors. So, if you have a constructor that allocates a resource and a destructor that deallocates the same resource, both functions typically have the same priority. The priorities for constructor and destructor functions are the same as those specified for namespace-scope C++ objects (see C++ Attributes).

尝试参考一下这个过一遍相关的知识：https://zdyxry.github.io/2020/04/12/runc-nsenter-%E6%BA%90%E7%A0%81%E9%98%85%E8%AF%BB/

### 代码结构
根据cgo和nsenter本身的代码块，我们会进入init，init函数利用了GNU的语法糖，在runc init程序跑起来之前，就能优先地运行
```go
//go:build linux && !gccgo

package nsenter

/*
#cgo CFLAGS: -Wall
extern void nsexec();
void __attribute__((constructor)) init(void) {
	nsexec();
}
*/
import "C"
```
很自然地我们进入到nsexec函数中，这个函数是runc init的核心
```go
void nsexec(void)
{
	int pipenum;
	jmp_buf env;
	int sync_child_pipe[2], sync_grandchild_pipe[2];
	struct nlconfig_t config = { 0 };

	/*
	 * Setup a pipe to send logs to the parent. This should happen
	 * first, because bail will use that pipe.
	 */
	// 设置了logpipe的类型
	// LOGPIPE和LOGLEVEL的值被设置起来，其中LOGPIPE的关闭标志着runc init执行的完毕
	setup_logpipe();

	/*
	 * Get the init pipe fd from the environment. The init pipe is used to
	 * read the bootstrap data and tell the parent what the new pids are
	 * after the setup is done.
	 */
	// init pipe 用于读取启动进程时的数据，并且在启动后，告诉父亲进程新的pids是什么
	// 这个管道标志着容器runc init进程，如果找不到这个环境变量，那么就说明不是runc init
	pipenum = getenv_int("_LIBCONTAINER_INITPIPE");
	if (pipenum < 0) {
		/* We are not a runc init. Just return to go runtime. */
		return;
	}

	write_log(DEBUG, "=> nsexec container setup");

	/* Log initial CPU affinity, this is solely for the tests in
	 * ../../tests/integration/cpu_affinity.bats.
	 *
	 * Logging this from Go code might be too late as some kernels
	 * change the process' CPU affinity to that of container's cpuset
	 * as soon as the process is moved into container's cgroup.
	 */
	// cgroup可能会在一定程度上修改亲和性，这表示着将某个进程或者线程绑定到特定CPU上的能力，而不会调度到其他核心上
	log_cpu_affinity();

	/* Parse all of the netlink configuration. */
	// Netlink的信息是Linux内核和用户之间的通信机制，用于传递内核事件和配置数据
	// 通过socket来进行实现，允许内核和用户之间进行双向通信
	// 
	// 在runc create的时候，通过管道创建了下面的对，而runc init对饮的是initSockChild，因此能够接收到
	// 与之对应的initSockParent对应的具体信息
	// 而runc create进程会把bootstrapData传递过去
	// 这边会对应上config.json中的一部分配置信息，从父进程这边的data传递过去
	// cmd.ExtraFiles = append(cmd.ExtraFiles, comm.initSockChild)
	// cmd.Env = append(cmd.Env,
	// 	"_LIBCONTAINER_INITPIPE="+strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1),
	// )
	// 在runc中，主要用于这边config中明示的几种类型
	nl_parse(pipenum, &config);

	/* Set oom_score_adj. This has to be done before !dumpable because
	 * /proc/self/oom_score_adj is not writeable unless you're an privileged
	 * user (if !dumpable is set). All children inherit their parent's
	 * oom_score_adj value on fork(2) so this will always be propagated
	 * properly.
	 */
	// 与OOM和不可转储相关，算是细枝末节，是作为防护用的
	update_oom_score_adj(config.oom_score_adj, config.oom_score_adj_len);

	/*
	 * Make the process non-dumpable, to avoid various race conditions that
	 * could cause processes in namespaces we're joining to access host
	 * resources (or potentially execute code).
	 *
	 * However, if the number of namespaces we are joining is 0, we are not
	 * going to be switching to a different security context. Thus setting
	 * ourselves to be non-dumpable only breaks things (like rootless
	 * containers), which is the recommendation from the kernel folks.
	 */
	if (config.namespaces) {
		write_log(DEBUG, "set process as non-dumpable");
		if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
			bail("failed to set process as non-dumpable");
	}

	/* Pipe so we can tell the child when we've finished setting up. */
	// 似乎在这里又创建了两个管道，这两个管道一个是和儿子做同步，另外一个被用于和孙子做同步
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sync_child_pipe) < 0)
		bail("failed to setup sync pipe between parent and child");

	/*
	 * We need a new socketpair to sync with grandchild so we don't have
	 * race condition with child.
	 */
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sync_grandchild_pipe) < 0)
		bail("failed to setup sync pipe between parent and grandchild");

	/* TODO: Currently we aren't dealing with child deaths properly. */

	/*
	 * Okay, so this is quite annoying.
	 *
	 * In order for this unsharing code to be more extensible we need to split
	 * up unshare(CLONE_NEWUSER) and clone() in various ways. The ideal case
	 * would be if we did clone(CLONE_NEWUSER) and the other namespaces
	 * separately, but because of SELinux issues we cannot really do that. But
	 * we cannot just dump the namespace flags into clone(...) because several
	 * usecases (such as rootless containers) require more granularity around
	 * the namespace setup. In addition, some older kernels had issues where
	 * CLONE_NEWUSER wasn't handled before other namespaces (but we cannot
	 * handle this while also dealing with SELinux so we choose SELinux support
	 * over broken kernel support).
	 *
	 * However, if we unshare(2) the user namespace *before* we clone(2), then
	 * all hell breaks loose.
	 *
	 * The parent no longer has permissions to do many things (unshare(2) drops
	 * all capabilities in your old namespace), and the container cannot be set
	 * up to have more than one {uid,gid} mapping. This is obviously less than
	 * ideal. In order to fix this, we have to first clone(2) and then unshare.
	 *
	 * Unfortunately, it's not as simple as that. We have to fork to enter the
	 * PID namespace (the PID namespace only applies to children). Since we'll
	 * have to double-fork, this clone_parent() call won't be able to get the
	 * PID of the _actual_ init process (without doing more synchronisation than
	 * I can deal with at the moment). So we'll just get the parent to send it
	 * for us, the only job of this process is to update
	 * /proc/pid/{setgroups,uid_map,gid_map}.
	 *
	 * And as a result of the above, we also need to setns(2) in the first child
	 * because if we join a PID namespace in the topmost parent then our child
	 * will be in that namespace (and it will not be able to give us a PID value
	 * that makes sense without resorting to sending things with cmsg).
	 *
	 * This also deals with an older issue caused by dumping cloneflags into
	 * clone(2): On old kernels, CLONE_PARENT didn't work with CLONE_NEWPID, so
	 * we have to unshare(2) before clone(2) in order to do this. This was fixed
	 * in upstream commit 1f7f4dde5c945f41a7abc2285be43d918029ecc5, and was
	 * introduced by 40a0d32d1eaffe6aac7324ca92604b6b3977eb0e. As far as we're
	 * aware, the last mainline kernel which had this bug was Linux 3.12.
	 * However, we cannot comment on which kernels the broken patch was
	 * backported to.
	 *
	 * -- Aleksa "what has my life come to?" Sarai
	 */
	// 一些机制的解析：
	// unshare: 创建一个新的命名空间并且把当前进程移入其中
	// setns: 将当前进程加入到一个已经有的命名空间中
	// 此处的设计细节考虑了非常多棘手的问题，包括rootless情况的特殊处理，为了方便理解，我们暂时不考虑设计成现在这种模式的原因
		// setjmp是和longjmp一起配合使用的，
		// setjmp保存了当前的上下文到env变量中，以方便子进程和孙进程进入到这个节点中
		// 进入的结点恰好是这个env位置
		// 
		// 总体来说，三个进程是避免不了的
		// 如果是两个进程
		// 1. PID namespace下PID为1的root进程有特殊处理，可能无法与父进程进行交互
		// 2. runc没法进入PID namespace（他还要自己处理其他事情），无法与容器进程交互
		// 三个进程的好处是解耦开了功能，通过中间的子进程完成了runc的通信交互过程
		switch (setjmp(env)) {
		/*
		 * Stage 0: We're in the parent. Our job is just to create a new child
		 *          (stage 1: STAGE_CHILD) process and write its uid_map and
		 *          gid_map. That process will go on to create a new process, then
		 *          it will send us its PID which we will send to the bootstrap
		 *          process.
		 */
		 // 首先进入父进程这边，也就是一开始的runc init进程主要目的是创建一个child进程
		 // 此外，它也负责写uid_map和gid_map数据结构，同时还得告诉bootstrap进程信息
		 // 更加底部的信息可能是从子进程和孙进程那边间接获得的
		 // 
		 // 父进程实际上还在原本宿主机的命名空间中，因此起码要有两个进程
	case STAGE_PARENT:{
			int len;
			pid_t stage1_pid = -1, stage2_pid = -1;
			bool stage1_complete, stage2_complete;

			/* For debugging. */
			current_stage = STAGE_PARENT;
			// 设置父进程的名称为第二个参数所示的字符串
			prctl(PR_SET_NAME, (unsigned long)"runc:[0:PARENT]", 0, 0, 0);
			write_log(DEBUG, "~> nsexec stage-0");

			/* Start the process of getting a container. */
			write_log(DEBUG, "spawn stage-1");
			// 通过clone的方式，跑起来同样的进程
			// 但是STAGE_CHILD被设置到了env中，因此之后会跑起来分支二，其他不变
			stage1_pid = clone_parent(&env, STAGE_CHILD);
			if (stage1_pid < 0)
				bail("unable to spawn stage-1");

			// 之前创建的和子进程进行通信的管道，在父进程这边做好设置
			// 特别的，通过socketpair建立的pipe似乎是可以双向读写的
			// 但还是关闭掉0，这个口是子进程传输信息用的
			syncfd = sync_child_pipe[1];
			if (close(sync_child_pipe[0]) < 0)
				bail("failed to close sync_child_pipe[0] fd");

			/*
			 * State machine for synchronisation with the children. We only
			 * return once both the child and grandchild are ready.
			 */
			write_log(DEBUG, "-> stage-1 synchronisation loop");
			stage1_complete = false;
			// 等待stage1_complete转化为True的时刻
			while (!stage1_complete) {
				// 枚举类型用来告知父进程底下子进程和孙进程的情况
				enum sync_t s;

				// 从子进程那边得到运行的结果是什么样子的
				// 根据s来确认信息结果
				if (read(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with stage-1: next state");
				// 对此进行解析
				switch (s) {
				// 由child发送的第一个请求，要求其对usermap做映射和修改
				case SYNC_USERMAP_PLS:
					write_log(DEBUG, "stage-1 requested userns mappings");

					/*
					 * Enable setgroups(2) if we've been asked to. But we also
					 * have to explicitly disable setgroups(2) if we're
					 * creating a rootless container for single-entry mapping.
					 * i.e. config.is_setgroup == false.
					 * (this is required since Linux 3.19).
					 *
					 * For rootless multi-entry mapping, config.is_setgroup shall be true and
					 * newuidmap/newgidmap shall be used.
					 */
					if (config.is_rootless_euid && !config.is_setgroup)
						update_setgroups(stage1_pid, SETGROUPS_DENY);

					/* Set up mappings. */
					// 本质上是在host的视角上，对/proc/stage1_pid/uid_mappings做的修改，让其值和uidmap是一样的
					// 后面的gidmap也是在stage1_pid目录下做的修改，此处的文件系统已经展开了，看起来确实不大好防御
					update_uidmap(config.uidmappath, stage1_pid, config.uidmap, config.uidmap_len);
					update_gidmap(config.gidmappath, stage1_pid, config.gidmap, config.gidmap_len);

					// 完成了stage1_pid的uidmap设置之后，就结束了，把对应的信息发送回去
					s = SYNC_USERMAP_ACK;
					if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
						sane_kill(stage1_pid, SIGKILL);
						sane_kill(stage2_pid, SIGKILL);
						bail("failed to sync with stage-1: write(SYNC_USERMAP_ACK)");
					}
					break;
				// 收到了这个请求之后，爷进程会跑到这个分支做处理
				case SYNC_RECVPID_PLS:
					write_log(DEBUG, "stage-1 requested pid to be forwarded");

					/* Get the stage-2 pid. */
					// 进一步阅读syncfd内容，从而得到stage2_pid
					if (read(syncfd, &stage2_pid, sizeof(stage2_pid)) != sizeof(stage2_pid)) {
						sane_kill(stage1_pid, SIGKILL);
						bail("failed to sync with stage-1: read(stage2_pid)");
					}

					/* Send ACK. */
					// 收到后，发信息给子进程，告知我已经知道孙子进程的进程号
					s = SYNC_RECVPID_ACK;
					if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
						sane_kill(stage1_pid, SIGKILL);
						sane_kill(stage2_pid, SIGKILL);
						bail("failed to sync with stage-1: write(SYNC_RECVPID_ACK)");
					}

					/*
					 * Send both the stage-1 and stage-2 pids back to runc.
					 * runc needs the stage-2 to continue process management,
					 * but because stage-1 was spawned with CLONE_PARENT we
					 * cannot reap it within stage-0 and thus we need to ask
					 * runc to reap the zombie for us.
					 */
					// clone_parent的意义：让新创建的进程本质上是我的siblings，
					// 共享一个父亲，也就是runc，所以本质上runc要负责对于stage-1做回收
					write_log(DEBUG, "forward stage-1 (%d) and stage-2 (%d) pids to runc",
						  stage1_pid, stage2_pid);
					// 从pipenum中，把stage1_pid和stage2_pid的信息送回去
					len =
					    dprintf(pipenum, "{\"stage1_pid\":%d,\"stage2_pid\":%d}\n", stage1_pid,
						    stage2_pid);
					if (len < 0) {
						sane_kill(stage1_pid, SIGKILL);
						sane_kill(stage2_pid, SIGKILL);
						bail("failed to sync with runc: write(pid-JSON)");
					}
					break;
				// 在timensoffset这个namespace下，会进入这个分支
				case SYNC_TIMEOFFSETS_PLS:
					write_log(DEBUG, "stage-1 requested timens offsets to be configured");
					// 同样是在/proc/stage1_pid下的timens_offsets上做的值的设置
					update_timens_offsets(stage1_pid, config.timensoffset, config.timensoffset_len);
					s = SYNC_TIMEOFFSETS_ACK;
					if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
						sane_kill(stage1_pid, SIGKILL);
						bail("failed to sync with child: write(SYNC_TIMEOFFSETS_ACK)");
					}
					break;
				// 父进程收到了这个信息，说明儿子马上就要退出了
				// 设置了stage1_complete，马上就要跳出这边的循环了
				case SYNC_CHILD_FINISH:
					write_log(DEBUG, "stage-1 complete");
					stage1_complete = true;
					break;
				default:
					bail("unexpected sync value: %u", s);
				}
			}
			write_log(DEBUG, "<- stage-1 synchronisation loop");

			/* Now sync with grandchild. */
			// 跳出循环后，现在就只有父进程和孙进程
			// 马不停蹄准备和孙进程一起通信
			syncfd = sync_grandchild_pipe[1];
			if (close(sync_grandchild_pipe[0]) < 0)
				bail("failed to close sync_grandchild_pipe[0] fd");

			write_log(DEBUG, "-> stage-2 synchronisation loop");
			stage2_complete = false;
			// 进入新的和孙进程交互的环节
			while (!stage2_complete) {
				enum sync_t s;

				write_log(DEBUG, "signalling stage-2 to run");
				// 告知孙进程，你可以跑了
				s = SYNC_GRANDCHILD;
				if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
					sane_kill(stage2_pid, SIGKILL);
					bail("failed to sync with child: write(SYNC_GRANDCHILD)");
				}

				if (read(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with child: next state");

				switch (s) {
				// 得到孙进程跑完的信息，马上就能跳出循环了
				case SYNC_CHILD_FINISH:
					write_log(DEBUG, "stage-2 complete");
					stage2_complete = true;
					break;
				default:
					bail("unexpected sync value: %u", s);
				}
			}
			// 跳出循环后，销毁自己，同样是使用runc来对自己进行reap处理
			write_log(DEBUG, "<- stage-2 synchronisation loop");
			write_log(DEBUG, "<~ nsexec stage-0");
			exit(0);
		}
		break;

		/*
		 * Stage 1: We're in the first child process. Our job is to join any
		 *          provided namespaces in the netlink payload and unshare all of
		 *          the requested namespaces. If we've been asked to CLONE_NEWUSER,
		 *          we will ask our parent (stage 0) to set up our user mappings
		 *          for us. Then, we create a new child (stage 2: STAGE_INIT) for
		 *          PID namespace. We then send the child's PID to our parent
		 *          (stage 0).
		 */
		 // 把自己加入netlink包中所示的namespaces中
		 // 创建所需要的namespaces，并自己加入之
		 // 对于CLONE_NEWUSER类型的namespaces
		 // - 会要求parent来负责对user mappings做处理
		 // - 为PID namespace创建孙进程，并告知父进程孙进程的PID
	case STAGE_CHILD:{
			pid_t stage2_pid = -1;
			enum sync_t s;

			/* For debugging. */
			current_stage = STAGE_CHILD;

			/* We're in a child and thus need to tell the parent if we die. */
			// 这个sync_child_pipe[0]是给子进程用的，和父进程进行交互
			// 子进程会从父进程那读写信息
			syncfd = sync_child_pipe[0];
			// 看起来关闭掉pipe1避免重复使用
			if (close(sync_child_pipe[1]) < 0)
				bail("failed to close sync_child_pipe[1] fd");

			/* For debugging. */
			prctl(PR_SET_NAME, (unsigned long)"runc:[1:CHILD]", 0, 0, 0);
			write_log(DEBUG, "~> nsexec stage-1");

			/*
			 * We need to setns first. We cannot do this earlier (in stage 0)
			 * because of the fact that we forked to get here (the PID of
			 * [stage 2: STAGE_INIT]) would be meaningless). We could send it
			 * using cmsg(3) but that's just annoying.
			 */
			if (config.namespaces)
			    // 首先通过spec中确认这些namespaces所对应的具体处理文件
				// 并事先打开对应的文件描述符，以保证自身可以对其做访问
				// 然后再通过setns一步一步慢慢先设置好对应的namespace中
				// 这一步疑似是专门先加入到namespace中去
				// ==================================================
				join_namespaces(config.namespaces);

			/*
			 * Deal with user namespaces first. They are quite special, as they
			 * affect our ability to unshare other namespaces and are used as
			 * context for privilege checks.
			 *
			 * We don't unshare all namespaces in one go. The reason for this
			 * is that, while the kernel documentation may claim otherwise,
			 * there are certain cases where unsharing all namespaces at once
			 * will result in namespace objects being owned incorrectly.
			 * Ideally we should just fix these kernel bugs, but it's better to
			 * be safe than sorry, and fix them separately.
			 *
			 * A specific case of this is that the SELinux label of the
			 * internal kern-mount that mqueue uses will be incorrect if the
			 * UTS namespace is cloned before the USER namespace is mapped.
			 * I've also heard of similar problems with the network namespace
			 * in some scenarios. This also mirrors how LXC deals with this
			 * problem.
			 */
			// 可能是因为一些特殊的考虑，在unshare之前先尝试做setns，或许是因为部分unshare做了之后，没有办法再做setns
			// 不过可以感觉到config.namespace中存放的似乎是已经有的namespace
			// 反之，unshare用的是config.cloneflags中的信息，用来保证自己能够去创建新的namespace
			if (config.cloneflags & CLONE_NEWUSER) {
				try_unshare(CLONE_NEWUSER, "user namespace");
				config.cloneflags &= ~CLONE_NEWUSER;

				/*
				 * We need to set ourselves as dumpable temporarily so that the
				 * parent process can write to our procfs files.
				 */
				if (config.namespaces) {
					write_log(DEBUG, "temporarily set process as dumpable");
					if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0)
						bail("failed to temporarily set process as dumpable");
				}

				/*
				 * We don't have the privileges to do any mapping here (see the
				 * clone_parent rant). So signal stage-0 to do the mapping for
				 * us.
				 */
				write_log(DEBUG, "request stage-0 to map user namespace");
				s = SYNC_USERMAP_PLS;
				if (write(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with parent: write(SYNC_USERMAP_PLS)");

				/* ... wait for mapping ... */
				write_log(DEBUG, "waiting stage-0 to complete the mapping of user namespace");
				if (read(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with parent: read(SYNC_USERMAP_ACK)");
				// 正常情况下会得到SYNC_USERMAP_ACK这个字段值
				if (s != SYNC_USERMAP_ACK)
					bail("failed to sync with parent: SYNC_USERMAP_ACK: got %u", s);

				/* Revert temporary re-dumpable setting. */
				if (config.namespaces) {
					write_log(DEBUG, "re-set process as non-dumpable");
					if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
						bail("failed to re-set process as non-dumpable");
				}

				/* Become root in the namespace proper. */
				// 似乎在NEWUSER字段下，会成为root
				if (setresuid(0, 0, 0) < 0)
					bail("failed to become root in user namespace");
			}

			/*
			 * Unshare all of the namespaces. Now, it should be noted that this
			 * ordering might break in the future (especially with rootless
			 * containers). But for now, it's not possible to split this into
			 * CLONE_NEWUSER + [the rest] because of some RHEL SELinux issues.
			 *
			 * Note that we don't merge this with clone() because there were
			 * some old kernel versions where clone(CLONE_PARENT | CLONE_NEWPID)
			 * was broken, so we'll just do it the long way anyway.
			 */
			// 对于剩下的unshare所展示的namespace做分配与设置
			try_unshare(config.cloneflags, "remaining namespaces");

			// 如果有timensoffset情况，则还是需要依赖stage-0来操作一下
			if (config.timensoffset) {
				write_log(DEBUG, "request stage-0 to write timens offsets");

				s = SYNC_TIMEOFFSETS_PLS;
				if (write(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with parent: write(SYNC_TIMEOFFSETS_PLS)");

				if (read(syncfd, &s, sizeof(s)) != sizeof(s))
					bail("failed to sync with parent: read(SYNC_TIMEOFFSETS_ACK)");
				// 在TIMEOFSSETS做好之后，返回ACK的字段
				if (s != SYNC_TIMEOFFSETS_ACK)
					bail("failed to sync with parent: SYNC_TIMEOFFSETS_ACK: got %u", s);
			}

			/*
			 * TODO: What about non-namespace clone flags that we're dropping here?
			 *
			 * We fork again because of PID namespace, setns(2) or unshare(2) don't
			 * change the PID namespace of the calling process, because doing so
			 * would change the caller's idea of its own PID (as reported by getpid()),
			 * which would break many applications and libraries, so we must fork
			 * to actually enter the new PID namespace.
			 */
			// 似乎是为了防止setns和unshare在PID namespace上出现紊乱，会改变程序正常运行
			// 的进程视角，所以可能还是希望把PID namespaces对于孙进程生效作为目标
			// 因此或许也可以说，先前的这些namespaces也是由子进程来设置，但是子进程本身也在
			// 这一部分namespaces中
			write_log(DEBUG, "spawn stage-2");
			// clone出来一个孙进程
			stage2_pid = clone_parent(&env, STAGE_INIT);
			if (stage2_pid < 0)
				bail("unable to spawn stage-2");

			/* Send the child to our parent, which knows what it's doing. */
			write_log(DEBUG, "request stage-0 to forward stage-2 pid (%d)", stage2_pid);
			s = SYNC_RECVPID_PLS;
			// 需要再发送一个信件，向家中老人介绍自己的孩子
			if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
				sane_kill(stage2_pid, SIGKILL);
				bail("failed to sync with parent: write(SYNC_RECVPID_PLS)");
			}
			// 立刻继续发送stage2_pid信息给爷进程
			if (write(syncfd, &stage2_pid, sizeof(stage2_pid)) != sizeof(stage2_pid)) {
				sane_kill(stage2_pid, SIGKILL);
				bail("failed to sync with parent: write(stage2_pid)");
			}

			/* ... wait for parent to get the pid ... */
			if (read(syncfd, &s, sizeof(s)) != sizeof(s)) {
				sane_kill(stage2_pid, SIGKILL);
				bail("failed to sync with parent: read(SYNC_RECVPID_ACK)");
			}
			// 收到了父进程对于孙进程的承认
			if (s != SYNC_RECVPID_ACK) {
				sane_kill(stage2_pid, SIGKILL);
				bail("failed to sync with parent: SYNC_RECVPID_ACK: got %u", s);
			}

			write_log(DEBUG, "signal completion to stage-0");
			s = SYNC_CHILD_FINISH;
			// 既然你已经知道了孙进程，我也做好了namespaces上设置的工作，
			// 那么我可以退出历史舞台了
			// 写完后马上跑，不给反映时间，让runc来reap自己
			if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
				sane_kill(stage2_pid, SIGKILL);
				bail("failed to sync with parent: write(SYNC_CHILD_FINISH)");
			}

			/* Our work is done. [Stage 2: STAGE_INIT] is doing the rest of the work. */
			write_log(DEBUG, "<~ nsexec stage-1");
			exit(0);
		}
		break;

		/*
		 * Stage 2: We're the final child process, and the only process that will
		 *          actually return to the Go runtime. Our job is to just do the
		 *          final cleanup steps and then return to the Go runtime to allow
		 *          init_linux.go to run.
		 */
	case STAGE_INIT:{
			/*
			 * We're inside the child now, having jumped from the
			 * start_child() code after forking in the parent.
			 */
			enum sync_t s;

			/* For debugging. */
			current_stage = STAGE_INIT;

			/* We're in a child and thus need to tell the parent if we die. */
			// 在子进程退出之后，孙进程开始考虑和父进程进行交互
			syncfd = sync_grandchild_pipe[0];
			if (close(sync_grandchild_pipe[1]) < 0)
				bail("failed to close sync_grandchild_pipe[1] fd");

			if (close(sync_child_pipe[0]) < 0)
				bail("failed to close sync_child_pipe[0] fd");

			/* For debugging. */
			prctl(PR_SET_NAME, (unsigned long)"runc:[2:INIT]", 0, 0, 0);
			write_log(DEBUG, "~> nsexec stage-2");

			if (read(syncfd, &s, sizeof(s)) != sizeof(s))
				bail("failed to sync with parent: read(SYNC_GRANDCHILD)");
			// 收到SYNC_GRANDCHILD之后，孙进程才开始跑，首先检查自己是否在当前
			// namespace中算是root进程
			if (s != SYNC_GRANDCHILD)
				bail("failed to sync with parent: SYNC_GRANDCHILD: got %u", s);

			if (setsid() < 0)
				bail("setsid failed");

			if (setuid(0) < 0)
				bail("setuid failed");

			if (setgid(0) < 0)
				bail("setgid failed");

			if (!config.is_rootless_euid && config.is_setgroup) {
				if (setgroups(0, NULL) < 0)
					bail("setgroups failed");
			}
			// 检查完之后，就算是跑完了？
			write_log(DEBUG, "signal completion to stage-0");
			s = SYNC_CHILD_FINISH;
			// 告知父进程，孙进程跑完了，之后父进程就会自己退出，孙进程真正继续往下跑
			if (write(syncfd, &s, sizeof(s)) != sizeof(s))
				bail("failed to sync with parent: write(SYNC_CHILD_FINISH)");

			/* Close sync pipes. */
			if (close(sync_grandchild_pipe[0]) < 0)
				bail("failed to close sync_grandchild_pipe[0] fd");

			/* Free netlink data. */
			nl_free(&config);

			/* Finish executing, let the Go runtime take over. */
			write_log(DEBUG, "<= nsexec container setup");
			write_log(DEBUG, "booting up go runtime ...");
			// 跑完return之后，我们进入C语言的终焉位置，但C语言部分就只是跑这一个函数
			// 存活到现在的因此就只有这一个孙进程
			// 先前的runc create会负责对父进程和子进程进行收割
			// 之后我们就跑到了runc init的剩余代码中
			return;
		}
		break;
	default:
		bail("unexpected jump value");
	}

	/* Should never be reached. */
	bail("should never be reached");
}
```
我们继续往下写，现在有必要继续捡起来这个东西了
```go
// 最后剩下的也就这么个玩意儿
func init() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		// This is the golang entry point for runc init, executed
		// before main() but after libcontainer/nsenter's nsexec().
		libcontainer.Init()
	}
}
// libcontainer/init_linux.go
func Init() {
	runtime.GOMAXPROCS(1)
	runtime.LockOSThread()

	if err := startInitialization(); err != nil {
		// If the error is returned, it was not communicated
		// back to the parent (which is not a common case),
		// so print it to stderr here as a last resort.
		//
		// Do not use logrus as we are not sure if it has been
		// set up yet, but most important, if the parent is
		// alive (and its log forwarding is working).
		fmt.Fprintln(os.Stderr, err)
	}
	// Normally, StartInitialization() never returns, meaning
	// if we are here, it had failed.
	os.Exit(255)
}
// 最后跑到这里
// libcontainer/standard_init_linux.go
	// Close all file descriptors we are not passing to the container. This is
	// necessary because the execve target could use internal runc fds as the
	// execve path, potentially giving access to binary files from the host
	// (which can then be opened by container processes, leading to container
	// escapes). Note that because this operation will close any open file
	// descriptors that are referenced by (*os.File) handles from underneath
	// the Go runtime, we must not do any file operations after this point
	// (otherwise the (*os.File) finaliser could close the wrong file). See
	// CVE-2024-21626 for more information as to why this protection is
	// necessary.
	if err := utils.UnsafeCloseFrom(l.config.PassedFilesCount + 3); err != nil {
		return err
	}
	return linux.Exec(name, l.config.Args, l.config.Env)
```
明儿调试一下，看起来这边的Exec就是我们先前写到cmd中的那个具体的命令，跟踪一下。

那么基本也就是说，runc init的孙进程最后会去通过调用Exec进程，直接去跑我们一开始要跑的那个命令

因此docker exec的原理和这边应该是一样的，docker run的话一般是跑sh这个，两者本质上没有区别，都是runc init跑到末尾一个Exec直接截胡