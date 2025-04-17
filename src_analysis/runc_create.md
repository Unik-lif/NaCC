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
	// 
	// 这边会涉及一个open的系统调用，然后会对这个做读取处理
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
	// 总之是建立了一个SOCKET负责通信
	notifySocket := newNotifySocket(context, os.Getenv("NOTIFY_SOCKET"), id)
	if notifySocket != nil {
        // 如果没有做设置，则从Spec中进行设置
		notifySocket.setupSpec(spec)
	}

    // 创建createContainer
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
    // 检查当前配置里头，rootlessCgroup的值的设置情况
	// 这边的检查似乎还是和systemd-cgroup有关系
	// --------------------------------------------------------
    // rootless表示的是，当前context中指定的信息是否是rootless模式的container
    // 如果没有指定，我们就去找euid，也就是启动当前这个runc create程序的进程的权限是什么，然后写到rootlessCg中
    // 如果当前euid为0,且不在namespace中运行，就说明是root
    // 如果当前euid为0,但是在namespace中，则需要通过管理cgroup机制的systemd机制来做检查，因为cgroup是创建container的进程来写的，通过找它的owner的权限情况，来确定是否当前需要rootless模式
	// 容器内表为root，有可能是基于namespace做的假象，关键还是容器进程本身owner是否是root，所以需要这个做检查
    // 如果实在没法确认，那就跑rootless，反正一定安全
	rootlessCg, err := shouldUseRootlessCgroupManager(context)
	if err != nil {
		return nil, err
	}

    // 这一步的配置非常麻烦，其中可能有很多配置信息是值得注意的
	// 最后得到的config文件是对Spec的高度凝练的结果，专门负责给libcontainer准备的
	config, err := specconv.CreateLibcontainerConfig(&specconv.CreateOpts{
        // 这边的id是cgroup作用的唯一标志符
		CgroupName:       id,
		UseSystemdCgroup: context.GlobalBool("systemd-cgroup"),
		NoPivotRoot:      context.Bool("no-pivot"),
		NoNewKeyring:     context.Bool("no-new-keyring"),
		Spec:             spec,
		RootlessEUID:     os.Geteuid() != 0,
		// 是否需要rootlesscgroups来做控制
		RootlessCgroups:  rootlessCg,
	})
	if err != nil {
		return nil, err
	}

	root := context.GlobalString("root")
	// 在有了对应的凝练config配置信息之后，我们通过libcontainer.create来进行创建
	return libcontainer.Create(root, id, config)
}
```
createContainer函数主要负责config的配置
- 检查当前创建的容器是否是需要root的，即是否rootless
- 创造为Libcontainer准备的Config文件
```go
// CreateLibcontainerConfig creates a new libcontainer configuration from a
// given specification and a cgroup name
func CreateLibcontainerConfig(opts *CreateOpts) (*configs.Config, error) {
	// runc's cwd will always be the bundle path
    // 得到bundle所对应的绝对路径，也是程序运行的位置的绝对路径
	// 绝对路径！
	cwd, err := getwd()
	if err != nil {
		return nil, err
	}
	// 确实opts中存放了先前读取的Spec信息
	spec := opts.Spec
	if spec.Root == nil {
		return nil, errors.New("root must be specified")
	}
    // rootfsPath一般来说，路径是在bundle路径下的一个子目录
	// 将其转化成rootfs的绝对路径
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
	// 其他Mount到容器内部的文件系统，对应的配置信息需要留存起来，记录在config.Mounts中
	for _, m := range spec.Mounts {
        // 将挂载的配置信息写入cm之中，相关的选项和ID均已经得到转化，并且记录在了cm之中
		// m需要是绝对路径
		// 这边还对Mount属性做了一些设置，一并写到mnt数据结构中
		// Mount对应的属性请具体看对应的系统调用，主要是Mount和Mount_setattr
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
    // 首先建立一个Cgroup的结构体，其中包括 是否使用SystemdCgroup，是否使用RootlessCgroups，以及 cgroups 对于全部资源访问的信息
    // ################################################
	// 1. 对于cgroups的使用，一般存在两种模式，首先是使用systemd来做，其次是通过直接操作cgroupfs来做，为什么较cgroupfs，是因为Linux为了操作方便，会允许/sys/fs/cgroup中的一些值采用类似于文件系统修改文件内容的方式来对其进行一些修改
	// 2. 内部的函数initSystemdProps似乎就只是对一些Systemd所对应的属性做了解析
	// 如果使用Systemd来做，则通过spec中的信息来做配置property，Systemd降低了配置和使用Cgroups的难度，但本质上似乎并无不同，可能只是方便了Cgroups的使用
	// 
    // 之后，明确了systemdCgroup的使用路径，已经当前Cgroup的名称
	// 
    // 3. 再根据spec中所写的不同资源，对其做资源做限制，包括 内存 CPU 进程数目 BlockIO 大页配置 RDMA 网络 以及 Unified Resources 资源，主要做的事情是把spec中对应的resources资源限制相关选项，读取到config文件中
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
        // 遍历我们spec文件中指定的不同的命名空间，如果命名空间类并不被支持，或者出现了重复，则返回错误，最后写道config中去
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
		// NEWNET表示隔离了网络栈，假设有configs.NEWNET恰好是Private类型，那就是自己固步自封的感觉了
		if config.Namespaces.IsPrivate(configs.NEWNET) {
			config.Networks = []*configs.Network{
				{
					Type: "loopback",
				},
			}
		}
        // 如果包含用户命名空间，则调用setupserNamespace函数设置用户命名空间，处理好这边的挂载点的ID映射
		// 容器内的用户可能是root，但是真实在Host系统中并不是
		if config.Namespaces.Contains(configs.NEWUSER) {
			// 具体的Mappings信息似乎在spec中都疑似写好了，因为确实有这个文件内容
			if err := setupUserNamespace(spec, config); err != nil {
				return nil, err
			}
			// For idmap and ridmap mounts without explicit mappings, use the
			// ones from the container's userns. If we are joining another
			// userns, stash the path.
			// mount系统似乎也需要做好对应的映射，否则host os不知道真实的用户权限是怎么样的
			// host os会在操作系统中维护ID与某些权限之间的关联
			// 看起来,host os中存在维护这样关系的数据链，它并没有实现的很漂亮，没有解耦开来
			// 这可能是一个相当大的设计挑战
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
			// 也就是对Seccomp中设置的一些syscall做了一下配置，将其转化成libcontainer中的格式
			// 以便后续进行使用
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
		// 似乎只要有一个挂上了RWCgroupfs标志，就会设置这个为True了
		for _, m := range config.Mounts {
			// 对所有Mounts的文件系统，做一些检查
			// 检查对应的Source是否为cgroup，对应的路径是否正确，以及是否是可以同时满足读写需求的
			// 容器的挂载点其实还包括proc，sys之类的
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
		// 这个说的确实是在容器自己NS下的UID，和真实的Host对应的UID不同
		processUid = int(spec.Process.User.UID)
	}
	if hasCgroupNS && hasRwCgroupfs {
		// 把processUID通过映射映射到Host OS机器上，得到ownerUID
		// 然后在Config上写上
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
		// 如果容器有独立的Cgroup命名空间，且挂载了可读写的cgroupfs，则将Cgroups.OwnerUID设置为运行容器进程的用户ID
		if err == nil {
			config.Cgroups.OwnerUID = &ownerUid
		}
	}
    // 进程属性与能力的限制
	// 如果这个字段是空的，那么就表示我们不需要为容器所对应的进程额外添加什么属性
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
这里出现了很多我没见过的名词，需要仔细地学习，了解其大意，可能也是create函数中最核心的一个部分，即通过手写地spec对应地config.json来做配置config
- Cgroup权限配置
- Namespace配置
- Personality配置
- seccomp配置
- capability配置

我们新开一个文件专门对这些配置做一些记录和研究，但其实所对应的东西也就那样，很零碎，我们不能被这些安全机制带到沟里去

到了这一步，我们基本已经完成了对于`spec`配置信息，以及其所配置的有哪些权限和设置的解读，接下来我们尝试继续向下分析研究。
```go
// Create creates a new container with the given id inside a given state
// directory (root), and returns a Container object.
//
// The root is a state directory which many containers can share. It can be
// used later to get the list of containers, or to get information about a
// particular container (see Load).
//
// The id must not be empty and consist of only the following characters:
// ASCII letters, digits, underscore, plus, minus, period. The id must be
// unique and non-existent for the given root path.
func Create(root, id string, config *configs.Config) (*Container, error) {
	if root == "" {
		return nil, errors.New("root not set")
	}
	// 这个ID需要是合法的，说白了就是由数字和字母来组成的
	if err := validateID(id); err != nil {
		return nil, err
	}
	// 在Validate步骤似乎完成了关于cgroupsCheck，rootfs，network，uts等等一系列的东西的检查
	if err := validate.Validate(config); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	stateDir, err := securejoin.SecureJoin(root, id)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(stateDir); err == nil {
		return nil, ErrExist
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	cm, err := manager.New(config.Cgroups)
	if err != nil {
		return nil, err
	}

	// Check that cgroup does not exist or empty (no processes).
	// Note for cgroup v1 this check is not thorough, as there are multiple
	// separate hierarchies, while both Exists() and GetAllPids() only use
	// one for "devices" controller (assuming others are the same, which is
	// probably true in almost all scenarios). Checking all the hierarchies
	// would be too expensive.
	if cm.Exists() {
		pids, err := cm.GetAllPids()
		// Reading PIDs can race with cgroups removal, so ignore ENOENT and ENODEV.
		if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENODEV) {
			return nil, fmt.Errorf("unable to get cgroup PIDs: %w", err)
		}
		if len(pids) != 0 {
			return nil, fmt.Errorf("container's cgroup is not empty: %d process(es) found", len(pids))
		}
	}

	// Check that cgroup is not frozen. Do not use Exists() here
	// since in cgroup v1 it only checks "devices" controller.
	st, err := cm.GetFreezerState()
	if err != nil {
		return nil, fmt.Errorf("unable to get cgroup freezer state: %w", err)
	}
	if st == cgroups.Frozen {
		return nil, errors.New("container's cgroup unexpectedly frozen")
	}

	// Parent directory is already created above, so Mkdir is enough.
	if err := os.Mkdir(stateDir, 0o711); err != nil {
		return nil, err
	}
	c := &Container{
		id:              id,
		stateDir:        stateDir,
		config:          config,
		cgroupManager:   cm,
		intelRdtManager: intelrdt.NewManager(config, id, ""),
	}
	c.state = &stoppedState{c: c}
	return c, nil
}
```

```go
func Validate(config *configs.Config) error {
	checks := []check{
		// 检查是否是Cgroup V1下的异常值，或者CgroupV2下的Memory Swap和Memory总量的配置是否正常（如果Swap的量比Memory总量还大，显然不正常）
		cgroupsCheck,
		// config.Rootfs需要是绝对路径，这边要保证这一点，保证它也不是符号链接
		rootfs,
		// 检查是否私有一个网络NS，如果不是，那关于Routes和Networks的配置都不可以存在，否则不合法
		network,
		// 在没有Hostname和Domainname的情况下，NEWUTS是不可以存在的
		uts,
		// 检查在MaskPaths和ReadonlyPaths做了配置的情况下，是否启用了挂载命名空间
		// MaskPaths: 容器内的进程没法访问的路径
		// ReadonlyPaths: 特定的系统路径对于容器的进程来说是只读的
		// 检查是否配置了SELinux标签，确保宿主机器使用了selinux，防止配置不一致
		security,
		// 在配置了NEWUSER时，需要保证/proc/self/ns/user下挂载了东西，还得保证存在NS Path或者UID/GID映射。如果没有NEWUSER，则不可以由Mapping
		// 如果有NEWCGOURP命名空间，则需要有/proc/self/ns/cgroup
		// 如果有NEWTIME命名空间，则需要有/proc/self/timens_offsets，如果TIMEOFFSETS和NS PATH均存在则返回错误，如果没有配置NEWTIME命名空间，则不能有Time Offsets
		namespaces,
		// sysctl的安全配置，包括IPC，网络，UTS相关的各种东西
		sysctl,
		// Intel部分特色机制
		intelrdtCheck,
		// 保证config can be applied，即便正在跑的这个runc它是non-root user
		// 必须要有NEWUSER，且有Mapping，必须要有所有的mounts下对应的uid/gid
		// 如果没有id=，则不可能有uid/gid，跳过检查
		// uid/gid的检查，在宿主机中一定有对应的，需要满足映射检查
		rootlessEUIDCheck,
		// 绑定挂载机制，不允许再重复挂载，以破坏原本文件系统的完整性
		// 禁用MOUNT_ATTR_IDMAP属性，确保ID映射挂载的配置合法并且完整
		mountsStrict,
		// 如果scheduler也做了设置，那么scheduler也需要合法，主要可能体现在某些场景下，必须是某些类型，且配置的优先级不能超出某个范围
		// 在指定了Priority时，也需要sched类型时特殊的调度策略
		scheduler,
		// IO优先级需要有效，然后对应的Class种类也得是固定的
		// 先Class后级别
		// Class分为激进实时和摆烂以及尽力而为型
		// 激进实时的哪怕优先级很低，也比尽力而为的最高优先级来说，更优先被调度
		ioPriority,
	}
	for _, c := range checks {
		if err := c(config); err != nil {
			return err
		}
	}
	// Relaxed validation rules for backward compatibility
	warns := []check{
		mountsWarn,
	}
	for _, c := range warns {
		if err := c(config); err != nil {
			logrus.WithError(err).Warn("configuration")
		}
	}
	return nil
}
```
