## Create流程分析
前几天的分析都比较小打小闹，有一些细节被我忽略了，而且网上的代码解析质量都曾差不齐的，以及代码版本可能存在不同，很难看，不如自己来。

现在着重来看这一部分。
```go
var createCommand = cli.Command{
	Name:  "create",
	Usage: "create a container",
	ArgsUsage: `<container-id>

Where "<container-id>" is your name for the instance of the container that you
are starting. The name you provide for the container instance must be unique on
your host.`,
	Description: `The create command creates an instance of a container for a bundle. The bundle
is a directory with a specification file named "` + specConfig + `" and a root
filesystem.

The specification file includes an args parameter. The args parameter is used
to specify command(s) that get run when the container is started. To change the
command(s) that get executed on start, edit the args parameter of the spec. See
"runc spec --help" for more explanation.`,
	Flags: []cli.Flag{
        // 包含有容器配置文件和根文件系统的文件路径，bundle
		cli.StringFlag{
			Name:  "bundle, b",
			Value: "",
			Usage: `path to the root of the bundle directory, defaults to the current directory`,
		},
        // AF_UNIX套间字可以允许用户与容器之间通过控制台终端来进行交互
		cli.StringFlag{
			Name:  "console-socket",
			Value: "",
			Usage: "path to an AF_UNIX socket which will receive a file descriptor referencing the master end of the console's pseudoterminal",
		},
        // 表示来自于init进程的描述符，以此可以对初始化进程做操作
		// [Marked]
        cli.StringFlag{
			Name:  "pidfd-socket",
			Usage: "path to an AF_UNIX socket which will receive a file descriptor referencing the init process",
		},
        // 可以把pid写入这个文件里头，以方便操作
		// [Marked]
        cli.StringFlag{
			Name:  "pid-file",
			Value: "",
			Usage: "specify the file to write the process id to",
		},
        // rootfs是容器的根文件系统，一般包含标准的Linux文件系统层次
        // 容器启动时，容器进程将会把这个目录视作自己的根目录
        // ramdisk是用内存作为储存的方案，在ramdisk上跑的rootfs的容器性能将变得很高
        // pivot_root会把原本在宿主机的一般进程的根文件系统转化为容器的根文件系统
        // 问题在于：在内存中的文件系统有易失性，所以会存在这样的禁用，避免挂载到位于内存上的根文件系统上
		cli.BoolFlag{
			Name:  "no-pivot",
			Usage: "do not use pivot root to jail process inside rootfs.  This should be used whenever the rootfs is on top of a ramdisk",
		},
        // 控制容器是否产生一个新的会话密钥环
        // keyring是Linux中用于安全存储和管理加密密钥等敏感信息的内核机制
        // 添加了keyring可以实现容器内进程的隔离，防止容器内进程访问宿主进程的密钥
        // 但是这本质上是安全容器，以及是内核防用户的机制，不在我们的考虑范围内
		cli.BoolFlag{
			Name:  "no-new-keyring",
			Usage: "do not create a new session keyring for the container.  This will cause the container to inherit the calling processes session key",
		},
        // 用于将额外的文件描述符传到容器中的进程，便于进程间通信或者资源共享
        // [Marked]
		cli.IntFlag{
			Name:  "preserve-fds",
			Usage: "Pass N additional file descriptors to the container (stdio + $LISTEN_FDS + N in total)",
		},
	},
    // 本质上是urfave/cli包中的原语，在接受cli.Context对象作为参数之后，就会执行下面的操作
	Action: func(context *cli.Context) error {
		if err := checkArgs(context, 1, exactArgs); err != nil {
			return err
		}
		status, err := startContainer(context, CT_ACT_CREATE, nil)
		if err == nil {
			// exit with the container's exit status so any external supervisor
			// is notified of the exit with the correct exit status.
			os.Exit(status)
		}
		return fmt.Errorf("runc create failed: %w", err)
	},
}
```
程序入口的createCommand
- 检查输入的参数个数是否符合，部分参数
- 利用startContainer来启动容器
```go
func startContainer(context *cli.Context, action CtAct, criuOpts *libcontainer.CriuOpts) (int, error) {
    // revisePidFile这一类函数
    // 要么返回nil，要么返回error
    // 这边是把pidFile对应的路径找到，转化为绝对路径，之后通过chdir就依旧能对其进行访问
	if err := revisePidFile(context); err != nil {
		return -1, err
	}
    // 首先通过chdir进入bundle所在的根文件系统
    // 之后通过loadSpec从config.json读取信息，对Spec数据结构做一些基本的填充
    // 其中包括对于容器内进程的定义，根文件系统，Hostname和Domainname之类的配置信息
	spec, err := setupSpec(context)
	if err != nil {
		return -1, err
	}
    // 返回了一个表示id的字符串，这个其实是用户所输入进去的，比如runc create demo1中，对应的id就是demo1
	id := context.Args().First()
	if id == "" {
		return -1, errEmptyID
	}
    // 从/run/runc这个存放容器状态的目录中引导出我们需要与Host OS进行交互的路径
    // notifySocket中不仅存放了NOTIFY_SOCKET指向的具体的host位置
    // 也存放了当前这个容器（从context中得到id用来做指向）用的socketPath对应位置
    // 似乎是和runc的host进行通信来的
	notifySocket := newNotifySocket(context, os.Getenv("NOTIFY_SOCKET"), id)
	if notifySocket != nil {
        // 如果没有做设置，则从Spec中进行设置
		notifySocket.setupSpec(spec)
	}

    // 
	container, err := createContainer(context, id, spec)
	if err != nil {
		return -1, err
	}

	if notifySocket != nil {
		if err := notifySocket.setupSocketDirectory(); err != nil {
			return -1, err
		}
		if action == CT_ACT_RUN {
			if err := notifySocket.bindSocket(); err != nil {
				return -1, err
			}
		}
	}

	// Support on-demand socket activation by passing file descriptors into the container init process.
	listenFDs := []*os.File{}
	if os.Getenv("LISTEN_FDS") != "" {
		listenFDs = activation.Files(false)
	}

	r := &runner{
		enableSubreaper: !context.Bool("no-subreaper"),
		shouldDestroy:   !context.Bool("keep"),
		container:       container,
		listenFDs:       listenFDs,
		notifySocket:    notifySocket,
		consoleSocket:   context.String("console-socket"),
		pidfdSocket:     context.String("pidfd-socket"),
		detach:          context.Bool("detach"),
		pidFile:         context.String("pid-file"),
		preserveFDs:     context.Int("preserve-fds"),
		action:          action,
		criuOpts:        criuOpts,
		init:            true,
	}
	return r.run(spec.Process)
}
```
对于其中的核心函数createContainer，我们做下面的分析
```go
func createContainer(context *cli.Context, id string, spec *specs.Spec) (*libcontainer.Container, error) {
    // 检查当前配置里头，rootless的值的设置情况
    // rootless表示的是，当前context中指定的信息是否是rootless模式的container
    // 如果没有指定，我们就去找euid，也就是启动当前这个runc create程序的进程的权限是什么，然后写到rootlessCg中
    // 如果当前euid为0,且不在namespace中运行，就说明是root
    // 如果当前euid为0,但是在namespace中，则需要通过管理cgroup机制的systemd机制来做检查，因为cgroup是创建container的进程来写的，通过找它的owner的权限情况，来确定是否当前需要rootless模式
    // 如果实在没法确认，那就跑rootless，反正一定安全
	rootlessCg, err := shouldUseRootlessCgroupManager(context)
	if err != nil {
		return nil, err
	}

    // 这一步的配置非常麻烦，其中可能有很多配置信息是值得注意的
	config, err := specconv.CreateLibcontainerConfig(&specconv.CreateOpts{
        // 这边的id是cgroup作用的唯一标志符
		CgroupName:       id,
		UseSystemdCgroup: context.GlobalBool("systemd-cgroup"),
		NoPivotRoot:      context.Bool("no-pivot"),
		NoNewKeyring:     context.Bool("no-new-keyring"),
		Spec:             spec,
		RootlessEUID:     os.Geteuid() != 0,
		RootlessCgroups:  rootlessCg,
	})
	if err != nil {
		return nil, err
	}

	root := context.GlobalString("root")
	return libcontainer.Create(root, id, config)
}
```
createContainer函数主要负责config的配置
- 检查当前创建的容器是否是需要root的，即是否rootless

```go
// CreateLibcontainerConfig creates a new libcontainer configuration from a
// given specification and a cgroup name
func CreateLibcontainerConfig(opts *CreateOpts) (*configs.Config, error) {
	// runc's cwd will always be the bundle path
    // 得到bundle所对应的绝对路径，也是程序运行的位置的绝对路径
	cwd, err := getwd()
	if err != nil {
		return nil, err
	}
	spec := opts.Spec
	if spec.Root == nil {
		return nil, errors.New("root must be specified")
	}
    // rootfsPath一般来说，路径是在bundle路径下的一个子目录
	rootfsPath := spec.Root.Path
	if !filepath.IsAbs(rootfsPath) {
		rootfsPath = filepath.Join(cwd, rootfsPath)
	}
	labels := []string{}
	for k, v := range spec.Annotations {
		labels = append(labels, k+"="+v)
	}
    // 在这边做了一系列的配置
	config := &configs.Config{
        // 根文件系统路径
		Rootfs:          rootfsPath,
		// 是否允许Pivot_Root，转变文件系统为rootfs中指向的那一个，与ramdisk方式有关
        NoPivotRoot:     opts.NoPivotRoot,
        // 是否设置根文件系统为只读，这样不用担心根文件系统被更改
		Readonlyfs:      spec.Root.Readonly,
		Hostname:        spec.Hostname,
		Domainname:      spec.Domainname,
		Labels:          append(labels, "bundle="+cwd),
		NoNewKeyring:    opts.NoNewKeyring,
		RootlessEUID:    opts.RootlessEUID,
		RootlessCgroups: opts.RootlessCgroups,
	}
    // 对于除了rootfs以外的挂载点情况
	for _, m := range spec.Mounts {
        // 将挂载的配置信息写入cm之中，相关的选项和ID均已经得到转化，并且记录在了cm之中
		cm, err := createLibcontainerMount(cwd, m)
		if err != nil {
			return nil, fmt.Errorf("invalid mount %+v: %w", m, err)
		}
        // 把挂载信息进一步存储在config.Mounts之中
		config.Mounts = append(config.Mounts, cm)
	}

    // 包含块设备等信息，还从spec中读取支持的设备，创建相应的设备配置，写到config里头
    // defaultDevs中的设备则已经去重了
	defaultDevs, err := createDevices(spec, config)
	if err != nil {
		return nil, err
	}
    // 首先建立一个Cgroup的结构体，其中包括 是否使用SystemdCgroup 是否使用RootlessCgroups 以及 cgroups 对于全部资源访问的信息
    // 如果使用Systemd来做，则通过spec中的信息来做配置property，Systemd降低了配置和使用Cgroups的难度
    // 之后，明确了systemdCgroup的使用路径，已经当前Cgroup的名称
    // 再根据spec中所写的不同资源，对其做资源做限制，包括 内存 CPU 进程数目 BlockIO 大页配置 RDMA 网络 以及 Unified Resources 资源
    // 一股脑写到了这个c里头，作为config信息的总结
    // defaultDevs的配置信息是最后加的边角料，是直接在resources.devices中加上的，而且只记录了其中的使用规则
	c, err := CreateCgroupConfig(opts, defaultDevs)
	if err != nil {
		return nil, err
	}

	config.Cgroups = c
	// set linux-specific config
	if spec.Linux != nil {
        // 将spec中的namespace信息映射到configs中
        // 将挂载传播选项字符串映射到unix常量
        // 做了以上事情之后，配置过程已经得到了一定的简化
		initMaps()

        // 文件系统的挂载传播选项，决定了之后的容器的文件系统挂载是否会受到宿主机的影响，或者反过来影响到宿主机
		if spec.Linux.RootfsPropagation != "" {
			var exists bool
			if config.RootPropagation, exists = mountPropagationMapping[spec.Linux.RootfsPropagation]; !exists {
				return nil, fmt.Errorf("rootfsPropagation=%v is not supported", spec.Linux.RootfsPropagation)
			}
            // 是NoPivotRoot，而且传播选项还是private，这种情况是不存在的
			if config.NoPivotRoot && (config.RootPropagation&unix.MS_PRIVATE != 0) {
				return nil, errors.New("rootfsPropagation of [r]private is not safe without pivot_root")
			}
		}
        // 遍历我们spec文件中指定的不同的命名空间，如果命名空间类并不被支持，或者出现了重复，则返回错误
		for _, ns := range spec.Linux.Namespaces {
			t, exists := namespaceMapping[ns.Type]
			if !exists {
				return nil, fmt.Errorf("namespace %q does not exist", ns)
			}
            if config.Namespaces.Contains(t) {
				return nil, fmt.Errorf("malformed spec file: duplicated ns %q", ns)
			}
			config.Namespaces.Add(t, ns.Path)
		}
        // 网络的命名空间，如果是私有的，自然写个loopback就行
		if config.Namespaces.IsPrivate(configs.NEWNET) {
			config.Networks = []*configs.Network{
				{
					Type: "loopback",
				},
			}
		}
        // 如果包含用户命名空间，则调用setupserNamespace函数设置用户命名空间，处理好这边的挂载点的ID映射
		if config.Namespaces.Contains(configs.NEWUSER) {
			if err := setupUserNamespace(spec, config); err != nil {
				return nil, err
			}
			// For idmap and ridmap mounts without explicit mappings, use the
			// ones from the container's userns. If we are joining another
			// userns, stash the path.
			for _, m := range config.Mounts {
				if m.IDMapping != nil && m.IDMapping.UIDMappings == nil && m.IDMapping.GIDMappings == nil {
					if path := config.Namespaces.PathOf(configs.NEWUSER); path != "" {
						m.IDMapping.UserNSPath = path
					} else {
						m.IDMapping.UIDMappings = config.UIDMappings
						m.IDMapping.GIDMappings = config.GIDMappings
					}
				}
			}
		}
		config.MaskPaths = spec.Linux.MaskedPaths
		config.ReadonlyPaths = spec.Linux.ReadonlyPaths
		config.MountLabel = spec.Linux.MountLabel
		config.Sysctl = spec.Linux.Sysctl
		config.TimeOffsets = spec.Linux.TimeOffsets
        // Seccomp机制，限制进程对于系统调用的使用
		if spec.Linux.Seccomp != nil {
			seccomp, err := SetupSeccomp(spec.Linux.Seccomp)
			if err != nil {
				return nil, err
			}
			config.Seccomp = seccomp
		}
        // Intel的某个特殊的机制
		if spec.Linux.IntelRdt != nil {
			config.IntelRdt = &configs.IntelRdt{
				ClosID:        spec.Linux.IntelRdt.ClosID,
				L3CacheSchema: spec.Linux.IntelRdt.L3CacheSchema,
				MemBwSchema:   spec.Linux.IntelRdt.MemBwSchema,
			}
		}
        // 与进程运行时所相关的选项，允许修改进程的某些行为
        // 似乎主要时为了调整进程的ABI行为，和架构有点关系
		if spec.Linux.Personality != nil {
			if len(spec.Linux.Personality.Flags) > 0 {
				logrus.Warnf("ignoring unsupported personality flags: %+v because personality flag has not supported at this time", spec.Linux.Personality.Flags)
			}
            // 这边会返回，当前Linux环境是否支持所需要的Personality特性
			domain, err := getLinuxPersonalityFromStr(string(spec.Linux.Personality.Domain))
			if err != nil {
				return nil, err
			}
			config.Personality = &configs.LinuxPersonality{
				Domain: domain,
			}
		}

	}

	// Set the host UID that should own the container's cgroup.
	// This must be performed after setupUserNamespace, so that
	// config.HostRootUID() returns the correct result.
	//
	// Only set it if the container will have its own cgroup
	// namespace and the cgroupfs will be mounted read/write.
	//
    // 检查容器是否有自己的cgroup命名空间
	hasCgroupNS := config.Namespaces.IsPrivate(configs.NEWCGROUP)
	hasRwCgroupfs := false
	if hasCgroupNS {
        // 检查是否容器挂载了可读写的cgroup文件系统
		for _, m := range config.Mounts {
			if m.Source == "cgroup" && filepath.Clean(m.Destination) == "/sys/fs/cgroup" && (m.Flags&unix.MS_RDONLY) == 0 {
				hasRwCgroupfs = true
				break
			}
		}
	}
	processUid := 0
	if spec.Process != nil {
		// Chown the cgroup to the UID running the process,
		// which is not necessarily UID 0 in the container
		// namespace (e.g., an unprivileged UID in the host
		// user namespace).
        // 获取容器内运行进程的UID
		processUid = int(spec.Process.User.UID)
	}
	if hasCgroupNS && hasRwCgroupfs {
        // 容器内的UID转换为宿主的UID
        // 宿主机UID为cgroup的持有者
		ownerUid, err := config.HostUID(processUid)
		// There are two error cases; we can ignore both.
		//
		// 1. uidMappings is unset.  Either there is no user
		//    namespace (fine), or it is an error (which is
		//    checked elsewhere).
		//
		// 2. The user is unmapped in the user namespace.  This is an
		//    unusual configuration and might be an error.  But it too
		//    will be checked elsewhere, so we can ignore it here.
		//
		if err == nil {
			config.Cgroups.OwnerUID = &ownerUid
		}
	}
    // 进程属性与能力的限制
	if spec.Process != nil {
		config.OomScoreAdj = spec.Process.OOMScoreAdj
		config.NoNewPrivileges = spec.Process.NoNewPrivileges
		config.Umask = spec.Process.User.Umask
		config.ProcessLabel = spec.Process.SelinuxLabel
		if spec.Process.Capabilities != nil {
			config.Capabilities = &configs.Capabilities{
				Bounding:    spec.Process.Capabilities.Bounding,
				Effective:   spec.Process.Capabilities.Effective,
				Permitted:   spec.Process.Capabilities.Permitted,
				Inheritable: spec.Process.Capabilities.Inheritable,
				Ambient:     spec.Process.Capabilities.Ambient,
			}
		}
		if spec.Process.Scheduler != nil {
			s := *spec.Process.Scheduler
			config.Scheduler = &s
		}

		if spec.Process.IOPriority != nil {
			ioPriority := *spec.Process.IOPriority
			config.IOPriority = &ioPriority
		}
		config.ExecCPUAffinity, err = configs.ConvertCPUAffinity(spec.Process.ExecCPUAffinity)
		if err != nil {
			return nil, err
		}

	}
    // 钩子并不总是必要的
	createHooks(spec, config)
	config.Version = specs.Version
	return config, nil
}
```
这里出现了很多我没见过的名词，需要仔细地学习，了解其大意，可能也是create函数中最核心地一个部分，即通过手写地spec对应地config.json来做配置config