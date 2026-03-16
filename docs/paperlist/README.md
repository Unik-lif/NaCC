# NaCC 论文筛选入口

更新时间：2026-03-14

这份文档不是论文清单，而是后续筛论文时的“问题地图”。目标是先把 NaCC 当前做到哪里、真正卡在哪里、以及应该往哪些计算抽象上扩展视野，先讲清楚。后续新增论文时，建议都先回答这里的问题，再决定是否值得细读。

## 1. NaCC 目前在做什么

基于当前仓库里的 `docs/agent/*.md` 与 `record/*.md`，NaCC 可以先理解成：

- 一个面向 RISC-V 的 confidential container 原型系统
- 保护核心不在 guest VM，而在更细粒度的“机密容器进程”
- 机制上依赖：
  - Linux 内核打钩子，接管 fork / exec / reclaim / page table 相关路径
  - OpenSBI monitor 在 M-mode 管理安全页表页（PTP）与关键映射
  - Agent 负责用户态 trap 代理与机密上下文保存

和常见 “在 stage-2 / nested paging 上做隔离” 的方案相比，NaCC 更像是在直接改写 Linux 进程地址空间与页表生命周期。这也是它最有意思、也最难做对的地方。

## 2. 目前已经走到哪一步

从最近材料看，NaCC 已经不只是概念验证，而是进入了“机制逐步收口”的阶段：

- fork 路径已经形成了一个明确方案：
  - Linux 跳过常规 `copy_page_range()`
  - OpenSBI 复制 child 用户页表树
  - Linux 再补齐 child 页表页 metadata（`ptdesc` / PTL ctor）
- same-PID `re-exec` 主路径已经基本跑通
- 现在的问题不再是“完全起不来”，而是：
  - trap save page 的 reexec 可达性
  - 页表页 metadata 生命周期尾部一致性
  - Linux 语义状态与硬件运行状态的一致性

换句话说，NaCC 已经跨过了“有没有机制”这一步，正在进入“机制何时正确、边界何在、抽象能否说清”这一步。

## 3. 我目前理解的核心困扰

这些困扰可以分成三层。

### 3.1 工程层

- same-PID `reexec` 中，agent 的 `_user_context` 这类 runtime page 并没有天然落在固定 remap 区间里
- `Bad page state`、RSS 记账、页表页 metadata 构造与回收，说明 Linux 自身的内存元数据语义还在和 NaCC 机制拉扯
- `thread.nacc_flag` 与 `CSR_NACC_STATE` 是两套状态机，稍有时序错位就会出现“Linux 认为还在 NaCC，硬件却不这么认为”的卡住或异常

### 3.2 机制层

- NaCC 当前最核心的选择，是“让 monitor 直接参与页表复制、回收与再挂接”
- 这条路比“OS 正常做，monitor 事后验证”更强，也更侵入 Linux 语义
- fork / exec / reexec / reclaim 不是几个补丁点，而是一条连续的地址空间生命周期

因此当前真正的问题不是“某个 bug 怎么修”，而是：

- 哪些状态迁移必须由 Linux 主导
- 哪些页表事实必须以 monitor 为准
- 哪些运行时数据必须固定化，不能依赖动态补映射

### 3.3 研究层

从已有记录里已经能看出一个更大的问题：  
很多相关工作会尽量避免直接碰 fork 过程本身，而是让 OS 正常完成，再由 monitor/CSM 事后验证和接管。NaCC 现在这条路线则更深入 Linux mm 语义本体。

这会导向几个很值得思考的研究问题：

- 页表到底应该被看作“普通内核元数据”，还是“需要独立保护与生命周期管理的安全对象”？
- 机密执行的最小可信抽象，究竟是进程、地址空间、容器，还是“若干关键内核对象”？
- trap 上下文、页表元数据、地址空间切换这三件事，能否被统一到同一个抽象里？
- 当系统要支持 fork / exec / reexec 这类 Linux 原生语义时，monitor 应该“替代 OS”还是“验证 OS”？

这几条会直接决定后面论文应该怎么筛。

## 4. 后续筛论文，不建议只找“像 NaCC 的系统”

如果只找“也是 confidential container / secure monitor / page table protection”的论文，容易把视野卡死在系统实现对比上。更合适的筛法，应该按问题簇来建表。

### 4.1 第一簇：机密容器 / 机密进程系统

目标：

- 看别人如何定义 TCB、保护边界、性能目标
- 看 fork / exec / signal / page fault 这类 OS 语义是否被正面处理

### 4.2 第二簇：页表保护与地址空间完整性

目标：

- 看页表在文献中被当成什么对象
- 看“保护页表页”与“维护 Linux 元数据一致性”之间如何折中

### 4.3 第三簇：monitor-OS 协作模型

目标：

- 看 monitor 是直接接管、事后验证，还是做某种可证明的双边协议
- 看系统边界在哪一层最稳定

### 4.4 第四簇：进程生命周期语义

目标：

- 专门关注 fork / exec / reexec / COW / reclaim
- 这类论文可能不一定叫 confidential computing，但对 NaCC 的问题非常关键

### 4.5 第五簇：更高层的计算抽象

目标：

- 超出容器安全本身，去看“受保护计算单元”到底该如何抽象
- 例如 capability、language runtime、unikernel / libOS、microkernel、proof-oriented isolation 这些方向

这部分对你后博士阶段想扩宽视野尤其重要，因为它不再局限于“把当前系统补完”，而是开始回答“下一个系统该建立在什么抽象上”。

## 5. 我建议后面给每篇论文都打这几类标签

- `问题域`：confidential container / page table protection / monitor verification / OS abstraction / fork-exec semantics
- `保护对象`：进程 / 容器 / 地址空间 / 页表 / trap context / 内核对象
- `协作方式`：OS 主导 / monitor 主导 / monitor 事后验证 / 双边协议
- `fork/exec`：正面支持 / 只支持 exec / 回避不谈 / 不适用
- `对 NaCC 的价值`：可直接借鉴机制 / 可借鉴评价方法 / 可借鉴问题定义 / 仅作对照
- `抽象启发`：它在提醒我们“该把什么当作一等公民”

## 6. 下一步建议

后面我会按这个入口继续做两件事：

1. 先整理一版“优先筛选的论文方向和代表工作”
2. 再逐篇给出中文摘要，重点不是复述内容，而是回答：
   - 它解决了什么问题
   - 它回避了什么问题
   - 它对 NaCC 是工程借鉴，还是研究启发

目前这份文档只基于仓库内材料整理，尚未开始联网筛论文。
