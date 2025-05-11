## Create流程分析
### 配置文件spec与其余设置
重点放在容器落实的机制，原理层面。

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

	// 通过notifySocket和systemd来进行通信，监控容器状态
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
	// spec.Process表示给container process做configuration的Process
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
	// 建一个root作为根地址 The root is a state directory which many containers can share.
	// 如果目录已经存在，mkdirall并不会报错
	// If path is already a directory, MkdirAll does nothing and returns nil.
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	// 避免路径逃逸，保证信息将会被存放在root下
	// root对应的路径在上面已经建立起来了
	stateDir, err := securejoin.SecureJoin(root, id)
	if err != nil {
		return nil, err
	}
	// 按照常理来说会得到一个好的StateDir，记录root目录下id存放的地址，然后解析也将会是正确的
	if _, err := os.Stat(stateDir); err == nil {
		return nil, ErrExist
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	// 根据config.Cgroups信息来得到对应版本的cgroup manager
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
		// 读cgroup.procs下有哪些进程
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
	// Freezer是用于冻结cgroup下进程的东西
	// 当前容器还没有跑起来，freezer不应该处于冻结状态
	st, err := cm.GetFreezerState()
	if err != nil {
		return nil, fmt.Errorf("unable to get cgroup freezer state: %w", err)
	}
	if st == cgroups.Frozen {
		return nil, errors.New("container's cgroup unexpectedly frozen")
	}

	// Parent directory is already created above, so Mkdir is enough.
	// root对应的路径已经建立起来了，现在则考虑把stateDir也建立起来
	// 每个容器真正自身对应的路径，其他人似乎是有执行的权利
	if err := os.Mkdir(stateDir, 0o711); err != nil {
		return nil, err
	}
	// 建立一个Container的数据结构
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
根据config中的信息，做了下面的事情
- 为容器创建路径，id与stateDir
- 为容器配置其所对应的config和cgroupManager（版本需要合适）

一些简单的检查功能放在这边了
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
结论，create流程目前做的事情是
- 根据spec配置了config信息，有很多杂七杂八锅碗瓢盆的东西
- 做了基本的权限配置检查，防止其不合理
- 调用libcontainer的Create，创建了一个Container数据结构体，内嵌了其可被复用的root路径地址，和自身用的StateDir路径地址

### runner机制
runc程序有较好的封装，我们接下来重点关注runner在诸如create，start等容器操作中扮演的角色

在建立完相关的数据结构后，startContainer中含有下面的部分
```go
// init表示确实是第一个进程
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
```
只在这里确实看不出这些字段的作用，我们看run操作
```go
func (r *runner) run(config *specs.Process) (int, error) {
	var err error
	// defer会把下面的函数延迟到run函数跑完再跑，如果出错，直接销毁
	defer func() {
		if err != nil {
			r.destroy()
		}
	}()
	// 容器要么依赖分配的tty去和终端链接，要么不需要tty，在这两种情况下，分别需要或者不需要设置控制台socket
	// 排查的是这个配置问题
	if err = r.checkTerminal(config); err != nil {
		return -1, err
	}
	// 将配置用的进程config映射到libcontainer内部
	// 其对应的UID，GID等配置都按照spec.Process中的配置来
	process, err := newProcess(config)
	if err != nil {
		return -1, err
	}
	// 在 create 情况下，r.init 为 True，确实是第一个进程
	// 可以理解成 process 是 config 在 container 中的映射，并没有真的新创建了一个新的进程
	process.LogLevel = strconv.Itoa(int(logrus.GetLevel()))
	// Populate the fields that come from runner.
	process.Init = r.init
	// 在create中似乎这个变量没有被初始化
	process.SubCgroupPaths = r.subCgroupPaths
	if len(r.listenFDs) > 0 {
		process.Env = append(process.Env, "LISTEN_FDS="+strconv.Itoa(len(r.listenFDs)), "LISTEN_PID=1")
		process.ExtraFiles = append(process.ExtraFiles, r.listenFDs...)
	}
	baseFd := 3 + len(process.ExtraFiles)
	// 打开并锁定当前这个进程，防止被调度走
	// 跑完了再关掉，重新调度
	// 检查并保留额外的文件描述符，确保它们再容器进程中是可用的
	// ProcThreadSelf文件目录下对应的几个FDs => 以及对应的假的文件
	procSelfFd, closer := utils.ProcThreadSelf("fd/")
	defer closer()
	for i := baseFd; i < baseFd+r.preserveFDs; i++ {
		_, err = os.Stat(filepath.Join(procSelfFd, strconv.Itoa(i)))
		if err != nil {
			return -1, fmt.Errorf("unable to stat preserved-fd %d (of %d): %w", i-baseFd, r.preserveFDs, err)
		}
		process.ExtraFiles = append(process.ExtraFiles, os.NewFile(uintptr(i), "PreserveFD:"+strconv.Itoa(i)))
	}
	// 如果是create，或者本身r中也写了detach为true，之后可能确实会detach
	detach := r.detach || (r.action == CT_ACT_CREATE)
	// Setting up IO is a two stage process. We need to modify process to deal
	// with detaching containers, and then we get a tty after the container has
	// started.
	// 为容器设置控制台等IO接口
	handlerCh := newSignalHandler(r.enableSubreaper, r.notifySocket)
	tty, err := setupIO(process, r.container, config.Terminal, detach, r.consoleSocket)
	if err != nil {
		return -1, err
	}
	defer tty.Close()

	// 如果指定了pidfdocket，则调用PID文件描述符套间字，以实现和容器进程通信
	if r.pidfdSocket != "" {
		connClose, err := setupPidfdSocket(process, r.pidfdSocket)
		if err != nil {
			return -1, err
		}
		defer connClose()
	}

	switch r.action {
	case CT_ACT_CREATE:
		err = r.container.Start(process)
	case CT_ACT_RESTORE:
		err = r.container.Restore(process, r.criuOpts)
	case CT_ACT_RUN:
		err = r.container.Run(process)
	default:
		panic("Unknown action")
	}
	if err != nil {
		return -1, err
	}
	// 等待控制台的初始化
	if err = tty.waitConsole(); err != nil {
		r.terminate(process)
		return -1, err
	}
	tty.ClosePostStart()
	// 创建PID文件路径
	if r.pidFile != "" {
		if err = createPidFile(r.pidFile, process); err != nil {
			r.terminate(process)
			return -1, err
		}
	}
	// 信号量相关，负责信号转发或者直接返回
	// 如果没啥异常，最后直接销毁runner容器
	handler := <-handlerCh
	status, err := handler.forward(process, tty, detach)
	if err != nil {
		r.terminate(process)
	}
	if detach {
		return 0, nil
	}
	if err == nil {
		r.destroy()
	}
	return status, err
}
```
**涉及文件操作的看上去并不多，主要有三类**
- 本身容器创建时对于spec文件的读取和解析
- 容器创建时的root路径和StateDir路径
- 一些杂七杂八的文件描述符和套间字暴露在外，用来和操作系统进行交互

负责交互的这一部分资源可能需要仔细考虑，分析确认其确实不会影响容器本身。除此之外，目前我们还没跑到镜像加载和基本文件系统的加载上，只是看上去象征性的为容器提供了一个对应的文件夹来做处理。

在create场景下，我们需要进一步研究函数r,container.create
```go
err = r.container.Start(process)

// Start starts a process inside the container. Returns error if process fails
// to start. You can track process lifecycle with passed Process structure.
// 这边的process是configuration process在libcontainer中的影子，特别注意
// 它并不是真正的容器进程，只不过有了容器进程的名，没有容器进程的实
func (c *Container) Start(process *Process) error {
	// container.mutex.lock()
	c.m.Lock()
	defer c.m.Unlock()
	return c.start(process)
}
```
进入到container的start函数中
```go
func (c *Container) start(process *Process) (retErr error) {
	if c.config.Cgroups.Resources.SkipDevices {
		return errors.New("can't start container with SkipDevices set")
	}

	if c.config.RootlessEUID && len(process.AdditionalGroups) > 0 {
		// We cannot set any additional groups in a rootless container
		// and thus we bail if the user asked us to do so.
		return errors.New("cannot set any additional groups in a rootless container")
	}
	// create操作会进入这个分支
	if process.Init {
		if c.initProcessStartTime != 0 {
			return errors.New("container already has init process")
		}
		// 在stateDir底下，创建了一个Fifo文件，设置其owner为rootuid，group为rootgid
		// 所有者有读写权利，其他人只有读的权利
		// FIFO为容器的初始化进程提供一个同步机制，用于协调容器的启动，比如等待容器初始化完成前，阻塞等待FIFO文件的操作
		// 确保容器安全并且可靠地启动
		if err := c.createExecFifo(); err != nil {
			return err
		}
		defer func() {
			if retErr != nil {
				c.deleteExecFifo()
			}
		}()
	}

	// 核心函数，需要仔细看和分析
	// 总之是套壳得到了一个parent类型的process，可是，它本质上也是process的套壳，只不过是设置成了containerProcess类型
	// 甚至目前这个对应的parent process也还只是一个配置信息，并没有真正地启动起来
	parent, err := c.newParentProcess(process)
	if err != nil {
		return fmt.Errorf("unable to create new parent process: %w", err)
	}
	// We do not need the cloned binaries once the process is spawned.
	defer process.closeClonedExes()

	logsDone := parent.forwardChildLogs()

	// Before starting "runc init", mark all non-stdio open files as O_CLOEXEC
	// to make sure we don't leak any files into "runc init". Any files to be
	// passed to "runc init" through ExtraFiles will get dup2'd by the Go
	// runtime and thus their O_CLOEXEC flag will be cleared. This is some
	// additional protection against attacks like CVE-2024-21626, by making
	// sure we never leak files to "runc init" we didn't intend to.
    // 这边主要是关闭对应的文件，似乎也不是那么重要
	if err := utils.CloseExecFrom(3); err != nil {
		return fmt.Errorf("unable to mark non-stdio fds as cloexec: %w", err)
	}
	// 这边看起来是重要的启动位置
	if err := parent.start(); err != nil {
		return fmt.Errorf("unable to start container process: %w", err)
	}

	if logsDone != nil {
		defer func() {
			// Wait for log forwarder to finish. This depends on
			// runc init closing the _LIBCONTAINER_LOGPIPE log fd.
			// LOGPIPE对应的pipe，将会告诉父亲进程，runc init已经跑完了
			err := <-logsDone
			if err != nil && retErr == nil {
				retErr = fmt.Errorf("unable to forward init logs: %w", err)
			}
		}()
	}

	// 后面是额外地添加hook的过程，并不重要
	if process.Init {
		c.fifo.Close()
		if c.config.HasHook(configs.Poststart) {
			s, err := c.currentOCIState()
			if err != nil {
				return err
			}
			// 容器创建成功后，运行前跑一些任务（runc init进程已经跑起来了）
			if err := c.config.Hooks.Run(configs.Poststart, s); err != nil {
				if err := ignoreTerminateErrors(parent.terminate()); err != nil {
					logrus.Warn(fmt.Errorf("error running poststart hook: %w", err))
				}
				return err
			}
		}
	}
	return nil
}


func (c *Container) newParentProcess(p *Process) (parentProcess, error) {
	// 用于同步父进程和子进程之间的数据传递
	comm, err := newProcessComm()
	if err != nil {
		return nil, err
	}

	// Make sure we use a new safe copy of /proc/self/exe binary each time, this
	// is called to make sure that if a container manages to overwrite the file,
	// it cannot affect other containers on the system. For runc, this code will
	// only ever be called once, but libcontainer users might call this more than
	// once.
	// 关闭现有的与Process相关的Exes文件，防止对于这些EXE文件的修改干扰到其他容器进程
	p.closeClonedExes()
	var (
		exePath string
		safeExe *os.File
	)
	// 判断是否这个exe已经被cloned了，如果是，那就不用做额外处理，不会影响到其他容器进程
	if exeseal.IsSelfExeCloned() {
		// /proc/self/exe is already a cloned binary -- no need to do anything
		logrus.Debug("skipping binary cloning -- /proc/self/exe is already cloned!")
		// We don't need to use /proc/thread-self here because the exe mm of a
		// thread-group is guaranteed to be the same for all threads by
		// definition. This lets us avoid having to do runtime.LockOSThread.
		exePath = "/proc/self/exe"
	} else {
		var err error
		// 先创建overlayfs文件系统包着，保证只读，然后把路径导入到safeExe中
		safeExe, err = exeseal.CloneSelfExe(c.stateDir)
		if err != nil {
			return nil, fmt.Errorf("unable to create safe /proc/self/exe clone for runc init: %w", err)
		}
		exePath = "/proc/self/fd/" + strconv.Itoa(int(safeExe.Fd()))
		p.clonedExes = append(p.clonedExes, safeExe)
		logrus.Debug("runc exeseal: using /proc/self/exe clone") // used for tests
	}

	cmd := exec.Command(exePath, "init")
	cmd.Args[0] = os.Args[0]
	cmd.Stdin = p.Stdin
	cmd.Stdout = p.Stdout
	cmd.Stderr = p.Stderr
	cmd.Dir = c.config.Rootfs
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &unix.SysProcAttr{}
	}
	cmd.Env = append(cmd.Env, "GOMAXPROCS="+os.Getenv("GOMAXPROCS"))
	cmd.ExtraFiles = append(cmd.ExtraFiles, p.ExtraFiles...)
	if p.ConsoleSocket != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, p.ConsoleSocket)
		cmd.Env = append(cmd.Env,
			"_LIBCONTAINER_CONSOLE="+strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1),
		)
	}

	cmd.ExtraFiles = append(cmd.ExtraFiles, comm.initSockChild)
	cmd.Env = append(cmd.Env,
		"_LIBCONTAINER_INITPIPE="+strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1),
	)
	cmd.ExtraFiles = append(cmd.ExtraFiles, comm.syncSockChild.File())
	cmd.Env = append(cmd.Env,
		"_LIBCONTAINER_SYNCPIPE="+strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1),
	)

	cmd.ExtraFiles = append(cmd.ExtraFiles, comm.logPipeChild)
	cmd.Env = append(cmd.Env,
		"_LIBCONTAINER_LOGPIPE="+strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1))
	if p.LogLevel != "" {
		cmd.Env = append(cmd.Env, "_LIBCONTAINER_LOGLEVEL="+p.LogLevel)
	}

	if p.PidfdSocket != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, p.PidfdSocket)
		cmd.Env = append(cmd.Env,
			"_LIBCONTAINER_PIDFD_SOCK="+strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1),
		)
	}

	// TODO: After https://go-review.googlesource.com/c/go/+/515799 included
	// in go versions supported by us, we can remove this logic.
	if safeExe != nil {
		// Due to a Go stdlib bug, we need to add safeExe to the set of
		// ExtraFiles otherwise it is possible for the stdlib to clobber the fd
		// during forkAndExecInChild1 and replace it with some other file that
		// might be malicious. This is less than ideal (because the descriptor
		// will be non-O_CLOEXEC) however we have protections in "runc init" to
		// stop us from leaking extra file descriptors.
		//
		// See <https://github.com/golang/go/issues/61751>.
		cmd.ExtraFiles = append(cmd.ExtraFiles, safeExe)

		// There is a race situation when we are opening a file, if there is a
		// small fd was closed at that time, maybe it will be reused by safeExe.
		// Because of Go stdlib fds shuffling bug, if the fd of safeExe is too
		// small, go stdlib will dup3 it to another fd, or dup3 a other fd to this
		// fd, then it will cause the fd type cmd.Path refers to a random path,
		// and it can lead to an error "permission denied" when starting the process.
		// Please see #4294.
		// So we should not use the original fd of safeExe, but use the fd after
		// shuffled by Go stdlib. Because Go stdlib will guarantee this fd refers to
		// the correct file.
		cmd.Path = "/proc/self/fd/" + strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1)
	}

	// NOTE: when running a container with no PID namespace and the parent
	//       process spawning the container is PID1 the pdeathsig is being
	//       delivered to the container's init process by the kernel for some
	//       reason even with the parent still running.
	if c.config.ParentDeathSignal > 0 {
		cmd.SysProcAttr.Pdeathsig = unix.Signal(c.config.ParentDeathSignal)
	}

	if p.Init {
		// We only set up fifoFd if we're not doing a `runc exec`. The historic
		// reason for this is that previously we would pass a dirfd that allowed
		// for container rootfs escape (and not doing it in `runc exec` avoided
		// that problem), but we no longer do that. However, there's no need to do
		// this for `runc exec` so we just keep it this way to be safe.
		// 把exec.fifo也加入到ExtraFiles中
		if err := c.includeExecFifo(cmd); err != nil {
			return nil, fmt.Errorf("unable to setup exec fifo: %w", err)
		}
		// 第一个进程会进入到这个分支里头
		return c.newInitProcess(p, cmd, comm)
	}
	return c.newSetnsProcess(p, cmd, comm)
}
```
newParentProcess的主要作用
- 容器为了防止/proc/self/exe文件本身被篡改，使用CloneSelfExe事先多拷贝一份出来进行使用，确保容器进程访问的并非runc的原始二进制文件，毕竟这个文件控制着容器的启动和管理。
- 调用newInitProcess来创建新的进程，或者调用newSetnsProcess。注意，根据我们先前的分析，目前容器中只有一个如假包换的进程（实际上是host进程套了马甲后的结果）

这边似乎涉及一些容器的术语。
- overlayfs是Linux的一个联合文件系统，允许在文件系统上创建一个只读层，被用来创建一个只读版本的exe，防止容器进程修改它
```go
// CloneSelfExe makes a clone of the current process's binary (through
// /proc/self/exe). This binary can then be used for "runc init" in order to
// make sure the container process can never resolve the original runc binary.
// For more details on why this is necessary, see CVE-2019-5736.
// tmpDir就是stateDir
func CloneSelfExe(tmpDir string) (*os.File, error) {
	// Try to create a temporary overlayfs to produce a readonly version of
	// /proc/self/exe that cannot be "unwrapped" by the container. In contrast
	// to CloneBinary, this technique does not require any extra memory usage
	// and does not have the (fairly noticeable) performance impact of copying
	// a large binary file into a memfd.
	//
	// Based on some basic performance testing, the overlayfs approach has
	// effectively no performance overhead (it is on par with both
	// MS_BIND+MS_RDONLY and no binary cloning at all) while memfd copying adds
	// around ~60% overhead during container startup.
	// 保护/proc/self/exe这个exe文件，通过创建一个overlayfs文件系统，设置可读，防止exe文件被篡改
	overlayFile, err := sealedOverlayfs("/proc/self/exe", tmpDir)
	if err == nil {
		// 正常情况下应该会进入这一分支
		logrus.Debug("runc exeseal: using overlayfs for sealed /proc/self/exe") // used for tests
		return overlayFile, nil
	}
	// 下面的是魔法，只要知道有这件事情就好了
	logrus.WithError(err).Debugf("could not use overlayfs for /proc/self/exe sealing -- falling back to making a temporary copy")

	selfExe, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, fmt.Errorf("opening current binary: %w", err)
	}
	defer selfExe.Close()

	stat, err := selfExe.Stat()
	if err != nil {
		return nil, fmt.Errorf("checking /proc/self/exe size: %w", err)
	}
	size := stat.Size()

	return CloneBinary(selfExe, size, "/proc/self/exe", tmpDir)
}

// sealedOverlayfs will create an internal overlayfs mount using fsopen() that
// uses the directory containing the binary as a lowerdir and a temporary tmpfs
// as an upperdir. There is no way to "unwrap" this (unlike MS_BIND+MS_RDONLY)
// and so we can create a safe zero-copy sealed version of /proc/self/exe.
// This only works for privileged users and on kernels with overlayfs and
// fsopen() enabled.
// 
// TODO: Since Linux 5.11, overlayfs can be created inside user namespaces so
// it is technically possible to create an overlayfs even for rootless
// containers. Unfortunately, this would require some ugly manual CGo+fork
// magic so we can do this later if we feel it's really needed.
func sealedOverlayfs(binPath, tmpDir string) (_ *os.File, Err error) {
	// Try to do the superblock creation first to bail out early if we can't
	// use this method.
	// fsopen是一个特殊系统调用，用于创建文件系统的上下文
	// overlayCtx是一个文件形式的上下文
	overlayCtx, err := fsopen("overlay", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return nil, err
	}
	defer overlayCtx.Close()

	// binPath is going to be /proc/self/exe, so do a readlink to get the real
	// path. overlayfs needs the real underlying directory for this protection
	// mode to work properly.
	// 得到binPath所对应的底层真实路径
	// 分割成目录部分和文件名部分
	if realPath, err := os.Readlink(binPath); err == nil {
		binPath = realPath
	}
	binLowerDirPath, binName := filepath.Split(binPath)
	// Escape any ":"s or "\"s in the path.
	binLowerDirPath = escapeOverlayLowerDir(binLowerDirPath)

	// Overlayfs requires two lowerdirs in order to run in "lower-only" mode,
	// where writes are completely blocked. Ideally we would create a dummy
	// tmpfs for this, but it turns out that overlayfs doesn't allow for
	// anonymous mountns paths.
	// NOTE: I'm working on a patch to fix this but it won't be backported.
	// 临时目录用作占位符号
	dummyLowerDirPath := escapeOverlayLowerDir(tmpDir)

	// Configure the lowerdirs. The binary lowerdir needs to be on the top to
	// ensure that a file called "runc" (binName) in the dummy lowerdir doesn't
	// mask the binary.
	// 看起来就是对exe这个文件的目录底下，开了一个tmpDir目录，作为真正的lowerdir，然后之后再保护起来
	lowerDirStr := binLowerDirPath + ":" + dummyLowerDirPath
	// FsconfigSetString设置OverlayFS的lowerdir参数
	// 相关的信息已经写到了overlayCtx.Fd()指向的具体的那个文件了
	// lowerDirStr表示只读目录的路径
	if err := unix.FsconfigSetString(int(overlayCtx.Fd()), "lowerdir", lowerDirStr); err != nil {
		return nil, fmt.Errorf("fsconfig set overlayfs lowerdir=%s: %w", lowerDirStr, err)
	}

	// We don't care about xino (Linux 4.17) but it will be auto-enabled on
	// some systems (if /run/runc and /usr/bin are on different filesystems)
	// and this produces spurious dmesg log entries. We can safely ignore
	// errors when disabling this because we don't actually care about the
	// setting and we're just opportunistically disabling it.
	_ = unix.FsconfigSetString(int(overlayCtx.Fd()), "xino", "off")

	// Get an actual handle to the overlayfs.
	// 把CMD做了设置，马上就创建了，需要在OverlayCtx中额外写入一部分信息
	if err := unix.FsconfigCreate(int(overlayCtx.Fd())); err != nil {
		return nil, os.NewSyscallError("fsconfig create overlayfs", err)
	}
	// 把文件系统挂载到overlayCtx所示的文件位置上，并且设置了其他的类型
	// 看起来就是只在/proc/self/exe之上建立了overlayfs类型的文件系统
	overlayFd, err := fsmount(overlayCtx, unix.FSMOUNT_CLOEXEC, unix.MS_RDONLY|unix.MS_NODEV|unix.MS_NOSUID)
	if err != nil {
		return nil, err
	}
	defer overlayFd.Close()

	// Grab a handle to the binary through overlayfs.
	exeFile, err := utils.Openat(overlayFd, binName, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s from overlayfs (lowerdir=%s): %w", binName, lowerDirStr, err)
	}
	// NOTE: We would like to check that exeFile is the same as /proc/self/exe,
	// except this is a little difficult. Depending on what filesystems the
	// layers are on, overlayfs can remap the inode numbers (and it always
	// creates its own device numbers -- see ovl_map_dev_ino) so we can't do a
	// basic stat-based check. The only reasonable option would be to hash both
	// files and compare them, but this would require fully reading both files
	// which would produce a similar performance overhead to memfd cloning.
	//
	// Ultimately, there isn't a real attack to be worried about here. An
	// attacker would need to be able to modify files in /usr/sbin (or wherever
	// runc lives), at which point they could just replace the runc binary with
	// something malicious anyway.
	return exeFile, nil
}
```
到这里确实完成了/proc/self/exe文件的克隆，接下来需要研究关键函数newInitProcess
```go
func (c *Container) newInitProcess(p *Process, cmd *exec.Cmd, comm *processComm) (*initProcess, error) {
	cmd.Env = append(cmd.Env, "_LIBCONTAINER_INITTYPE="+string(initStandard))
	nsMaps := make(map[configs.NamespaceType]string)
	for _, ns := range c.config.Namespaces {
		if ns.Path != "" {
			nsMaps[ns.Type] = ns.Path
		}
	}
	data, err := c.bootstrapData(c.config.Namespaces.CloneFlags(), nsMaps)
	if err != nil {
		return nil, err
	}
	// 套壳，使用了如假包换的进程
	init := &initProcess{
		containerProcess: containerProcess{
			cmd:           cmd,
			comm:          comm,
			manager:       c.cgroupManager,
			config:        c.newInitConfig(p),
			process:       p,
			bootstrapData: data,
			container:     c,
		},
		intelRdtManager: c.intelRdtManager,
	}
	c.initProcess = init
	return init, nil
}
```
而initProcess所对应的start函数如下所示，非常复杂，也是我们最核心需要分析的函数之一了：
```go
func (p *initProcess) start() (retErr error) {
	defer p.comm.closeParent()
	// 关键位置，启动cmd中记录的init程序，并跑起来它
	// 具体内容我们将会在runc_init中进行分析，这边先暂且不提及
	err := p.cmd.Start()
	p.process.ops = p
	// close the child-side of the pipes (controlled by child)
	p.comm.closeChild()
	if err != nil {
		p.process.ops = nil
		return fmt.Errorf("unable to start init: %w", err)
	}

	defer func() {
		if retErr != nil {
			// Find out if init is killed by the kernel's OOM killer.
			// Get the count before killing init as otherwise cgroup
			// might be removed by systemd.
			oom, err := p.manager.OOMKillCount()
			if err != nil {
				logrus.WithError(err).Warn("unable to get oom kill count")
			} else if oom > 0 {
				// Does not matter what the particular error was,
				// its cause is most probably OOM, so report that.
				const oomError = "container init was OOM-killed (memory limit too low?)"

				if logrus.GetLevel() >= logrus.DebugLevel {
					// Only show the original error if debug is set,
					// as it is not generally very useful.
					retErr = fmt.Errorf(oomError+": %w", retErr)
				} else {
					retErr = errors.New(oomError)
				}
			}

			// Terminate the process to ensure we can remove cgroups.
			// 确保通过terminate发送SIGKILL信号终止进程，确保清理了cgroup，销毁cgroup
			if err := ignoreTerminateErrors(p.terminate()); err != nil {
				logrus.WithError(err).Warn("unable to terminate initProcess")
			}

			_ = p.manager.Destroy()
			if p.intelRdtManager != nil {
				_ = p.intelRdtManager.Destroy()
			}
		}
	}()

	// Do this before syncing with child so that no children can escape the
	// cgroup. We don't need to worry about not doing this and not being root
	// because we'd be using the rootless cgroup manager in that case.
	// 将p.pid对应的进程，说白了就是runc init，加入到指定的cgroup中
	if err := p.manager.Apply(p.pid()); err != nil {
		if errors.Is(err, cgroups.ErrRootless) {
			// ErrRootless is to be ignored except when
			// the container doesn't have private pidns.
			if !p.config.Config.Namespaces.IsPrivate(configs.NEWPID) {
				// TODO: make this an error in runc 1.3.
				logrus.Warn("Creating a rootless container with no cgroup and no private pid namespace. " +
					"Such configuration is strongly discouraged (as it is impossible to properly kill all container's processes) " +
					"and will result in an error in a future runc version.")
			}
		} else {
			return fmt.Errorf("unable to apply cgroup configuration: %w", err)
		}
	}
	if p.intelRdtManager != nil {
		if err := p.intelRdtManager.Apply(p.pid()); err != nil {
			return fmt.Errorf("unable to apply Intel RDT configuration: %w", err)
		}
	}
	// 把bootstrapData写入到init对应的通道，runc init进程接收到会设置自身运行的namespaces数据等
	if _, err := io.Copy(p.comm.initSockParent, p.bootstrapData); err != nil {
		return fmt.Errorf("can't copy bootstrap data to pipe: %w", err)
	}
	// 获取子进程的PID
	// 也就是runc init中开的子进程
	childPid, err := p.getChildPid()
	if err != nil {
		return fmt.Errorf("can't get final child's PID from pipe: %w", err)
	}

	// Save the standard descriptor names before the container process
	// can potentially move them (e.g., via dup2()).  If we don't do this now,
	// we won't know at checkpoint time which file descriptor to look up.
	// 获得子进程的文件描述符路径
	fds, err := getPipeFds(childPid)
	if err != nil {
		return fmt.Errorf("error getting pipe fds for pid %d: %w", childPid, err)
	}
	p.setExternalDescriptors(fds)

	// Wait for our first child to exit
	if err := p.waitForChildExit(childPid); err != nil {
		return fmt.Errorf("error waiting for our first child to exit: %w", err)
	}

	// Spin up a goroutine to handle remapping mount requests by runc init.
	// There is no point doing this for rootless containers because they cannot
	// configure MOUNT_ATTR_IDMAP, nor do OPEN_TREE_CLONE. We could just
	// service plain-open requests for plain bind-mounts but there's no need
	// (rootless containers will never have permission issues on a source mount
	// that the parent process can help with -- they are the same user).
	var mountRequest mountSourceRequestFn
	// 启动一个goroutine，这个用户态线程，来负责处理之后的挂载请求
	// 会通过Setns系统调用，切换到容器所对应的挂载命名空间
	if !p.container.config.RootlessEUID {
		request, cancel, err := p.goCreateMountSources(context.Background())
		if err != nil {
			return fmt.Errorf("error spawning mount remapping thread: %w", err)
		}
		defer cancel()
		mountRequest = request
	}

	if err := p.createNetworkInterfaces(); err != nil {
		return fmt.Errorf("error creating network interfaces: %w", err)
	}

	// initConfig.SpecState is only needed to run hooks that are executed
	// inside a container, i.e. CreateContainer and StartContainer.
	if p.config.Config.HasHook(configs.CreateContainer, configs.StartContainer) {
		p.config.SpecState, err = p.container.currentOCIState()
		if err != nil {
			return fmt.Errorf("error getting current state: %w", err)
		}
	}

	// 序列化p.config的信息，从管道处发到runc init容器
	if err := utils.WriteJSON(p.comm.initSockParent, p.config); err != nil {
		return fmt.Errorf("error sending config to init process: %w", err)
	}

	var seenProcReady bool
	// 根据先前解析的序列化数据，依次解析下面的请求
	// 一直循环到socket关闭
	ierr := parseSync(p.comm.syncSockParent, func(sync *syncT) error {
		switch sync.Type {
		// 挂载类型的请求
		case procMountPlease:
			if mountRequest == nil {
				return fmt.Errorf("cannot fulfil mount requests as a rootless user")
			}
			var m *configs.Mount
			if sync.Arg == nil {
				return fmt.Errorf("sync %q is missing an argument", sync.Type)
			}
			if err := json.Unmarshal(*sync.Arg, &m); err != nil {
				return fmt.Errorf("sync %q passed invalid mount arg: %w", sync.Type, err)
			}
			mnt, err := mountRequest(m)
			if err != nil {
				return fmt.Errorf("failed to fulfil mount request: %w", err)
			}
			defer mnt.file.Close()

			arg, err := json.Marshal(mnt)
			if err != nil {
				return fmt.Errorf("sync %q failed to marshal mountSource: %w", sync.Type, err)
			}
			argMsg := json.RawMessage(arg)
			if err := doWriteSync(p.comm.syncSockParent, syncT{
				Type: procMountFd,
				Arg:  &argMsg,
				File: mnt.file,
			}); err != nil {
				return err
			}
		case procSeccomp:
			if p.config.Config.Seccomp.ListenerPath == "" {
				return errors.New("seccomp listenerPath is not set")
			}
			var srcFd int
			if sync.Arg == nil {
				return fmt.Errorf("sync %q is missing an argument", sync.Type)
			}
			if err := json.Unmarshal(*sync.Arg, &srcFd); err != nil {
				return fmt.Errorf("sync %q passed invalid fd arg: %w", sync.Type, err)
			}
			seccompFd, err := pidGetFd(p.pid(), srcFd)
			if err != nil {
				return fmt.Errorf("sync %q get fd %d from child failed: %w", sync.Type, srcFd, err)
			}
			defer seccompFd.Close()
			// We have a copy, the child can keep working. We don't need to
			// wait for the seccomp notify listener to get the fd before we
			// permit the child to continue because the child will happily wait
			// for the listener if it hits SCMP_ACT_NOTIFY.
			if err := writeSync(p.comm.syncSockParent, procSeccompDone); err != nil {
				return err
			}

			s, err := p.container.currentOCIState()
			if err != nil {
				return err
			}

			// initProcessStartTime hasn't been set yet.
			s.Pid = p.cmd.Process.Pid
			s.Status = specs.StateCreating
			containerProcessState := &specs.ContainerProcessState{
				Version:  specs.Version,
				Fds:      []string{specs.SeccompFdName},
				Pid:      s.Pid,
				Metadata: p.config.Config.Seccomp.ListenerMetadata,
				State:    *s,
			}
			if err := sendContainerProcessState(p.config.Config.Seccomp.ListenerPath,
				containerProcessState, seccompFd); err != nil {
				return err
			}
		case procReady:
			seenProcReady = true
			// Set rlimits, this has to be done here because we lose permissions
			// to raise the limits once we enter a user-namespace
			if err := setupRlimits(p.config.Rlimits, p.pid()); err != nil {
				return fmt.Errorf("error setting rlimits for ready process: %w", err)
			}

			// generate a timestamp indicating when the container was started
			p.container.created = time.Now().UTC()
			p.container.state = &createdState{
				c: p.container,
			}

			// NOTE: If the procRun state has been synced and the
			// runc-create process has been killed for some reason,
			// the runc-init[2:stage] process will be leaky. And
			// the runc command also fails to parse root directory
			// because the container doesn't have state.json.
			//
			// In order to cleanup the runc-init[2:stage] by
			// runc-delete/stop, we should store the status before
			// procRun sync.
			state, uerr := p.container.updateState(p)
			if uerr != nil {
				return fmt.Errorf("unable to store init state: %w", uerr)
			}
			p.container.initProcessStartTime = state.InitProcessStartTime

			// Sync with child.
			if err := writeSync(p.comm.syncSockParent, procRun); err != nil {
				return err
			}
		case procHooks:
			// Setup cgroup before prestart hook, so that the prestart hook could apply cgroup permissions.
			if err := p.manager.Set(p.config.Config.Cgroups.Resources); err != nil {
				return fmt.Errorf("error setting cgroup config for procHooks process: %w", err)
			}
			if p.intelRdtManager != nil {
				if err := p.intelRdtManager.Set(p.config.Config); err != nil {
					return fmt.Errorf("error setting Intel RDT config for procHooks process: %w", err)
				}
			}
			if p.config.Config.HasHook(configs.Prestart, configs.CreateRuntime) {
				s, err := p.container.currentOCIState()
				if err != nil {
					return err
				}
				// initProcessStartTime hasn't been set yet.
				s.Pid = p.cmd.Process.Pid
				s.Status = specs.StateCreating
				hooks := p.config.Config.Hooks

				if err := hooks.Run(configs.Prestart, s); err != nil {
					return err
				}
				if err := hooks.Run(configs.CreateRuntime, s); err != nil {
					return err
				}
			}
			// Sync with child.
			if err := writeSync(p.comm.syncSockParent, procHooksDone); err != nil {
				return err
			}
		default:
			return errors.New("invalid JSON payload from child")
		}
		return nil
	})

	if err := p.comm.syncSockParent.Shutdown(unix.SHUT_WR); err != nil && ierr == nil {
		return err
	}
	if !seenProcReady && ierr == nil {
		ierr = errors.New("procReady not received")
	}
	if ierr != nil {
		return fmt.Errorf("error during container init: %w", ierr)
	}
	return nil
}

// Start starts the specified command but does not wait for it to complete.
//
// If Start returns successfully, the c.Process field will be set.
//
// After a successful call to Start the [Cmd.Wait] method must be called in
// order to release associated system resources.
// 似乎主要是跑CMD所对应的命令，在启动的时候跑的其实就是runc init程序啦，因为cmd写了init作为参数
func (c *Cmd) Start() error {
	// Check for doubled Start calls before we defer failure cleanup. If the prior
	// call to Start succeeded, we don't want to spuriously close its pipes.
	if c.Process != nil {
		return errors.New("exec: already started")
	}

	started := false
	defer func() {
		closeDescriptors(c.childIOFiles)
		c.childIOFiles = nil

		if !started {
			closeDescriptors(c.parentIOPipes)
			c.parentIOPipes = nil
		}
	}()

	if c.Path == "" && c.Err == nil && c.lookPathErr == nil {
		c.Err = errors.New("exec: no command")
	}
	if c.Err != nil || c.lookPathErr != nil {
		if c.lookPathErr != nil {
			return c.lookPathErr
		}
		return c.Err
	}
	lp := c.Path
	if runtime.GOOS == "windows" {
		if c.Path == c.cachedLookExtensions.in {
			// If Command was called with an absolute path, we already resolved
			// its extension and shouldn't need to do so again (provided c.Path
			// wasn't set to another value between the calls to Command and Start).
			lp = c.cachedLookExtensions.out
		} else {
			// If *Cmd was made without using Command at all, or if Command was
			// called with a relative path, we had to wait until now to resolve
			// it in case c.Dir was changed.
			//
			// Unfortunately, we cannot write the result back to c.Path because programs
			// may assume that they can call Start concurrently with reading the path.
			// (It is safe and non-racy to do so on Unix platforms, and users might not
			// test with the race detector on all platforms;
			// see https://go.dev/issue/62596.)
			//
			// So we will pass the fully resolved path to os.StartProcess, but leave
			// c.Path as is: missing a bit of logging information seems less harmful
			// than triggering a surprising data race, and if the user really cares
			// about that bit of logging they can always use LookPath to resolve it.
			var err error
			lp, err = lookExtensions(c.Path, c.Dir)
			if err != nil {
				return err
			}
		}
	}
	if c.Cancel != nil && c.ctx == nil {
		return errors.New("exec: command with a non-nil Cancel was not created with CommandContext")
	}
	if c.ctx != nil {
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		default:
		}
	}

	childFiles := make([]*os.File, 0, 3+len(c.ExtraFiles))
	stdin, err := c.childStdin()
	if err != nil {
		return err
	}
	childFiles = append(childFiles, stdin)
	stdout, err := c.childStdout()
	if err != nil {
		return err
	}
	childFiles = append(childFiles, stdout)
	stderr, err := c.childStderr(stdout)
	if err != nil {
		return err
	}
	childFiles = append(childFiles, stderr)
	childFiles = append(childFiles, c.ExtraFiles...)

	env, err := c.environ()
	if err != nil {
		return err
	}
	// 跑起来一个进程，并同时设置了其所对应的一些参数
	// go语言对于进程创建的高级封装，涉及多个系统调用
	// 这边是跑起来init这个程序
	// 效果就是进入c.Dir所指向的文件处，根据相关的配置跑起来这个进程
	// lp其实就是path
	c.Process, err = os.StartProcess(lp, c.argv(), &os.ProcAttr{
		Dir:   c.Dir,
		Files: childFiles,
		Env:   env,
		Sys:   c.SysProcAttr,
	})
	if err != nil {
		return err
	}
	started = true

	// Don't allocate the goroutineErr channel unless there are goroutines to start.
	if len(c.goroutine) > 0 {
		goroutineErr := make(chan error, 1)
		c.goroutineErr = goroutineErr

		type goroutineStatus struct {
			running  int
			firstErr error
		}
		statusc := make(chan goroutineStatus, 1)
		statusc <- goroutineStatus{running: len(c.goroutine)}
		for _, fn := range c.goroutine {
			go func(fn func() error) {
				err := fn()

				status := <-statusc
				if status.firstErr == nil {
					status.firstErr = err
				}
				status.running--
				if status.running == 0 {
					goroutineErr <- status.firstErr
				} else {
					statusc <- status
				}
			}(fn)
		}
		c.goroutine = nil // Allow the goroutines' closures to be GC'd when they complete.
	}

	// If we have anything to do when the command's Context expires,
	// start a goroutine to watch for cancellation.
	//
	// (Even if the command was created by CommandContext, a helper library may
	// have explicitly set its Cancel field back to nil, indicating that it should
	// be allowed to continue running after cancellation after all.)
	if (c.Cancel != nil || c.WaitDelay != 0) && c.ctx != nil && c.ctx.Done() != nil {
		resultc := make(chan ctxResult)
		c.ctxResult = resultc
		go c.watchCtx(resultc)
	}

	return nil
}
```
到这边似乎算是分析完了，大体都看了一次。我们总结runc_create的作用如下
- 阅读配置文件spec，记录到p.config中去 -> 我们学习了namespace和cgroup，以及其他OS-Level隔离机制的特性和功能
- 跑runc create的进程通过套壳马甲，最终成功在容器中跑起来一个runc init进程，用runc init来负责初始化
- 最后runc create会等待由runc init发来的请求，并尝试同步并且处理

在完成了runc create后，我们很自然地会想去探索一下runc init做了什么

## 其他
主要参考内容：https://juejin.cn/post/6903527508784873485，用来帮助整体把控runc的代码框架