## TCG 课程学习
https://www.bilibili.com/video/BV1qcSJYmEMj?spm_id_from=333.788.player.switch&vd_source=49f5b184846e52adee8a1a5165c5f962

跟着华科开的小课程进行快速学习
```
src -> qemu IR -> target binary code

Guest               Host
```
在翻译的时候，TCG会以代码块来作为基本单元，翻译的产物为Translation Block，一般会有三种划分类型
- 分支指令
- 特权指令/异常
- 代码段出现跨页
在这三种情况下，得把TB给断开了，TB被封装成函数指针一样的类型，其中还有prologue和epilogue部分，用来处理TCG上下文信息

优化手段
- Direct Block Chaining: 想办法让tb之间的epilogue和prologue联系起来
- 缓存: 当一个Basic Block被DBT转化为TB之后，下次再执行到相同的Basic Block就可能可以从缓存中直接读取得到TB进行执行，如果没有的话，那还是得重新做翻译
- code buffer会在tcg_init_machine的时候进行申请和初始化，之后的代码翻译和执行的工作，都将围绕code buffer展开，TCGContext后端的管理工作，也会围绕code buffer进行

一种读代码的方式
- 先熟悉关键的数据结构，再从中找到感兴趣的结构
- 逐步往前追溯，来确认是否是我们所感兴趣的
- 第一次阅读，主要以感知为主，其他的暂时放在后头

大体重新过了一遍TB的生成过程，对这个东西有了点感觉，也快速学习了一下怎么新添加指令