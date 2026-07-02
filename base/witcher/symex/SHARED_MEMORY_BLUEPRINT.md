# Symex 双层 Master 共享内存实现蓝图

本文档不是面向最终用户的说明文档，而是后续修改 `witcher/symex` 时的执行蓝图。后续代码改造、文件新增、流程迁移、清理收口都以本文档为准。

## 1. 目标

- 在 Linux 环境下，把 `symex` 当前对大文件的“多进程重复解析/重复持有”改造成“双层 master + 只读共享映射 + 固定 worker 池”。
- 第一优先级共享：AST 相关文件。
- 第二优先级共享：trace 相关文件。
- 保持现有并发控制语义不变：
  - `max_branch_selector_procs`
  - `max_analyze_procs`
  - `max_analyze_concurrency`
- 保持当前 Witcher -> symex 的启动/停止信号链路兼容。
- 允许失败时回退到当前旧路径，不因共享层失败阻断现有流程。

## 2. 共享边界

### 2.1 全局共享边界

- 所有 `pipeline.py` 共享同一份 AST 数据。
- 所有 `analyze_if_line.py` 共享同一份 AST 数据。
- AST 数据是项目级稳定输入，不跟随单个 trace run 变化。

### 2.2 pipeline 私有共享边界

- 每个 `pipeline.py` 进程有一份独立的 trace 共享数据。
- 同一个 `pipeline.py` 拉起的全部 analyze worker 共享该 pipeline 的 trace 数据。
- 不同 `pipeline.py` 之间不共享 trace 数据。

### 2.3 结论

- 必须实现两级 master：
  - `Global AST Master`
  - `Pipeline Trace Master`
- 不允许用一个全局 master 同时托管所有 trace 数据。

## 3. 现状问题

当前热点路径：

- `branch_selector/pipeline.py`
  - 每个 pipeline 进程都会读取 `trace.log`、`trace_index.json`、`nodes.csv`、`rels.csv`
- `analyze_if_line.py`
  - 每个 analyze 子进程都会再次读取 `trace.log`、`trace_index.json`、`nodes.csv`、`rels.csv`

当前代价：

- 多个 Python 进程重复顺扫 GB 级文本文件。
- 多个 Python 进程重复把 CSV/JSON 解析成各自私有的 `dict/list`。
- 高并发时，CPU 时间浪费在重复解析上，RSS 浪费在重复对象上。
- 仅共享文件句柄不够，因为当前真正占用内存的是“解析后的 Python 对象”，不是 `open()` 本身。

## 4. 目标架构

### 4.1 总体拓扑

```text
Witcher
  -> symex_launcher.py
    -> symex/main.py --daemon
      -> Global AST Master (常驻，绑定整个 symex 生命周期)
      -> HybridTokenDaemon
        -> pipeline session #1
          -> Pipeline Trace Master #1 (常驻，绑定该 pipeline 生命周期)
          -> pipeline.py (控制面)
          -> Analyze Worker Pool #1..N (数据面，复用 analyze_if_line 逻辑)
        -> pipeline session #2
          -> Pipeline Trace Master #2
          -> pipeline.py
          -> Analyze Worker Pool #1..N
```

### 4.2 设计原则

- AST 使用全局共享。
- trace 使用 pipeline 局部共享。
- 共享对象必须是“只读 sidecar + mmap”，不能继续是进程私有 Python 大对象。
- analyze 执行从“每个 seq 拉起一个新进程”改为“每个 pipeline 下固定 worker 池重复处理任务”。
- 控制面和数据面分离：
  - `pipeline.py` 负责筛选、调度、并发闸门、日志
  - `Pipeline Trace Master + Analyze Worker Pool` 负责实际分析

## 5. 运行模式约束

### 5.1 平台约束

- 仅 Linux 启用共享内存优化。
- Windows 保持现有逻辑，不进入本文架构。

### 5.2 开关约束

新增配置开关：

- `symex_shared_memory.enabled`
- `symex_shared_memory.mode = "master_worker"`
- `symex_shared_memory.require_linux = true`
- `symex_shared_memory.fallback_legacy = true`

默认策略：

- Linux + enabled=true 时启用新架构。
- 任一 master 启动失败、sidecar 构建失败、attach 失败时，回退旧路径。
- 共享逻辑必须输出独立日志，至少覆盖：
  - bootstrap
  - attach/release
  - sidecar build/reuse
  - job submit/start/done
  - 失败原因与回退原因

### 5.3 失败停机约束

- 如果共享逻辑已经被选中为当前数据源，但由于 attach 失败、映射失败、读取失败或内容缺失导致当前进程拿不到所需文件内容，则不允许悄悄继续流程。
- 此时必须：
  1. 记录共享失败日志与状态文件
  2. 结束当前程序或当前受控子进程
  3. 由上层根据配置决定是否整体回退到旧路径
- 只有在“共享层尚未被正式启用，且配置允许 fallback_legacy”时，才允许回退到旧路径。

## 6. 文件与 sidecar 设计

## 6.1 全局 AST 原始文件

- `input/nodes.csv`
- `input/rels.csv`

## 6.2 全局 AST sidecar

目录建议：

- `<runtime_root>/shared_ast/`

文件清单：

- `nodes.meta.bin`
  - 节点基础字段的紧凑结构数组
- `nodes.strings.bin`
  - `code/name/doccomment/classname/namespace` 字符串池
- `rels.parent.bin`
  - `child_id -> parent_id`
- `rels.children.bin`
  - `parent_id -> [child_ids]` 的紧凑邻接表
- `ast.path_dict.bin`
  - 路径字符串字典和 `AST_TOPLEVEL` 映射
- `ast.header.json`
  - sidecar 版本、构建参数、校验信息、文件大小、mtime、字段布局

说明：

- 运行期主读取对象是 sidecar，不再直接读取 `nodes.csv/rels.csv`。
- 原始 CSV 只保留给 sidecar 构建与 fallback 使用。

## 6.3 pipeline trace 原始文件

- `<run_dir>/input/trace.log` 或当前等效 trace 位置
- `<run_dir>/tmp/trace_index.json`

## 6.4 pipeline trace sidecar

目录建议：

- `<run_dir>/shared_trace/`

文件清单：

- `trace.seq_index.bin`
  - `seq -> {path_id, line, record_id, raw_offset}`
- `trace.records.bin`
  - `record_id -> {path_id, line, seq_begin, seq_end, node_id_begin, node_id_count}`
- `trace.node_ids.bin`
  - record 对应的 node id 紧凑数组
- `trace.paths.bin`
  - trace path 字典
- `trace.raw_offsets.bin`
  - 若仍需回查原始 trace 行，存每个 seq 的偏移
- `trace.call_ranges.bin`
  - 可选；供少量 trace 区间扫描场景使用
- `trace.header.json`
  - 版本、构建参数、校验信息、布局

说明：

- 运行期主读取对象是 trace sidecar，不再把 `trace.log` / `trace_index.json` 作为主查询数据源。
- 原始 `trace.log` / `trace_index.json` 只保留给 sidecar 构建与 fallback 使用。

## 7. 进程模型

### 7.1 Global AST Master

新文件：

- `symex/shared_mem/global_ast_master.py`
- `symex/shared_mem/ast_sidecar_builder.py`
- `symex/shared_mem/ast_store.py`

职责：

- 校验 `nodes.csv/rels.csv` 是否变化。
- 构建或复用全局 AST sidecar。
- 打开全部 AST sidecar fd。
- 使用 `mmap(PROT_READ, MAP_SHARED)` 建立只读映射。
- 监听全局 UDS socket，处理 attach 请求。
- 为 pipeline session 提供 AST 映射句柄与元信息。
- 维护自身 pid、socket、header、健康状态。

IPC：

- socket 路径：`<runtime_root>/ipc/global_ast_master.sock`
- 协议：Unix domain socket + JSON header + `SCM_RIGHTS` 传递 fd

关键要求：

- Global AST Master 必须在 `main.py --daemon` 启动早期创建。
- 只允许存在一个活动实例。
- 退出前必须先拒绝新 attach，再等待 pipeline session 全部释放，再关闭映射。

### 7.2 Pipeline Trace Master

新文件：

- `symex/shared_mem/pipeline_trace_master.py`
- `symex/shared_mem/trace_sidecar_builder.py`
- `symex/shared_mem/trace_store.py`

职责：

- 连接 Global AST Master，attach AST sidecar fd。
- 构建或复用当前 run 的 trace sidecar。
- 打开 trace sidecar fd 并建立只读映射。
- 启动 analyze worker 池。
- 接收 `pipeline.py` 投递的 analyze 任务。
- 维护 owner pipeline pid、worker pid、inflight job、ref count。
- owner 退出且 worker 全部退出后完成自清理。

IPC：

- socket 路径：`<run_dir>/ipc/pipeline_trace_master.sock`
- 协议：Unix domain socket + JSON/msgpack

关键要求：

- 每个 pipeline session 对应一个 Trace Master。
- Trace Master 只服务一个 pipeline session。
- 不允许不同 pipeline 复用 trace sidecar。

### 7.3 Analyze Worker Pool

新文件：

- `symex/shared_mem/analyze_worker.py`
- `symex/shared_mem/analyze_job_protocol.py`
- `symex/shared_mem/analyze_core_adapter.py`

职责：

- 由 Pipeline Trace Master 启动固定数量 worker。
- worker attach AST + trace 共享映射。
- worker 从 master 取 job 并执行 analyze 逻辑。
- 每个 worker 处理多个 seq，不重复加载共享大文件。

数量：

- 默认池大小 = `max_analyze_concurrency`
- 但实际开始处理 job 前仍需受全局 token pool 限制

关键要求：

- worker 不再自行 `open nodes.csv/rels.csv/trace.log/trace_index.json`
- worker 内部只从共享 store 取数据
- worker 必须兼容现有 analyze 结果输出路径和日志格式

## 8. 控制面与数据面改造

### 8.1 pipeline.py 的角色变化

保留：

- branch selector 扫描
- prompt 构造
- LLM 调用
- `max_analyze_concurrency` 的本地并发闸门
- 全局 token 获取逻辑

移除：

- 直接 `create_subprocess_exec(analyze_if_line.py ...)`

替换为：

- attach `Pipeline Trace Master`
- 通过 master 投递 analyze job
- 等待 job 完成并回收结果

### 8.2 analyze_if_line.py 的角色变化

保留：

- 具体 analyze 逻辑
- 输出格式
- debug / llm / sql / xss / cmd 等模式分支

重构：

- 把当前 CLI 主流程拆成可复用核心函数
- 新增 worker entrypoint，从共享 store 读取 `seq/path/line/nodes/rels/trace_index`
- 旧 CLI 路径保留为 fallback 模式

必须新增抽象：

- `AnalyzeContextProvider`
  - 旧实现：从文件加载
  - 新实现：从共享 store 提供

### 8.3 graph_mapping / trace_index 使用方式变化

现有问题：

- `load_nodes()` / `load_ast_edges()` / `load_trace_index_records()` 当前默认按文件整表读入

重构目标：

- 新增共享 store API：
  - `get_node(node_id)`
  - `get_children(node_id)`
  - `get_parent(node_id)`
  - `get_record_for_seq(seq)`
  - `get_trace_loc(seq)`
  - `get_node_ids_for_record(record_id)`
- 旧文件加载 API 保留为 fallback

## 9. 并发控制兼容要求

### 9.1 不允许改变现有三层限制语义

- `max_branch_selector_procs`
  - 仍限制同时运行的 pipeline 数
- `max_analyze_procs`
  - 仍限制跨所有 pipeline 的 analyze 总量
- `max_analyze_concurrency`
  - 仍限制单个 pipeline 内可并发处理的 analyze 数

### 9.2 新架构中的对应关系

- `HybridTokenDaemon`
  - 继续决定是否启动新的 `pipeline.py`
- `pipeline.py`
  - 继续使用 `Semaphore(max_analyze_concurrency)`
- `Pipeline Trace Master`
  - worker 池大小默认等于 `max_analyze_concurrency`
- `Analyze Worker`
  - 真正开始 job 前必须拿 `analyze` token

### 9.3 兼容规则

- `pipeline.py` 提交 job 前先经过本地 semaphore
- worker 执行 job 前必须拿全局 `analyze` token
- job 完成后释放 token
- 若 token 获取失败或 master 不可用，可回退旧的 `analyze_if_line.py` 子进程模式

## 10. 生命周期与回收时机

### 10.1 全局 Global AST Master

绑定对象：

- 整个当前 symex daemon 生命周期

启动时机：

- `symex/main.py --daemon` 初始化早期
- 在 `HybridTokenDaemon` 创建之前启动

停止信号来源：

- Witcher `stop_symex()` 写 `stop.flag`
- Witcher 对 symex daemon `terminate()/kill()`
- daemon 收到 `SIGTERM` / `SIGINT`

停止流程：

1. daemon 发现 stop 条件
2. 停止拉起新 pipeline
3. 等待/回收现有 pipeline
4. 所有 pipeline session 结束后停止 Global AST Master
5. Global AST Master 关闭 socket、mmap、fd、pid/state 文件

关键要求：

- Global AST Master 必须监听：
  - 父 daemon pid
  - `runtime_root/meta/stop.flag`
  - `SIGTERM` / `SIGINT`

### 10.2 Pipeline Trace Master

绑定对象：

- 一个 `pipeline.py`
- 该 pipeline 下的全部 analyze worker

启动时机：

- `HybridTokenDaemon` 决定启动某个 pipeline session 时创建
- 在 `pipeline.py` 开始正式消费分析任务前完成 attach

停止条件：

- owner pipeline pid 已退出
- analyze worker 全部退出
- inflight jobs 为 0

清理判定：

- `owner_alive == false`
- `worker_count == 0`
- `inflight_jobs == 0`

则执行：

1. 停止接收新任务
2. 关闭 worker 池
3. 释放 trace mmap/fd
4. 删除 `<run_dir>/ipc/pipeline_trace_master.sock`
5. 删除 `<run_dir>/shared_trace/*.tmp`
6. 必要时删除私有 sidecar

### 10.3 泄漏防护

必须同时做三层保护：

- 正常 release
- pid 存活探测
- 超时/孤儿回收

实现要求：

- master 持有 owner pid 和 worker pid 列表
- 周期性检查 `/proc/<pid>` 或 `kill(pid, 0)`
- 若 worker 异常退出但未 release，自动减引用
- 若 owner 已死且所有 worker 已死，立即回收 pipeline master

## 11. 关闭文件与踢出内存策略

### 11.1 全局 AST 文件

原始文件：

- `nodes.csv`
- `rels.csv`

最后热路径使用时机：

- AST sidecar 构建完成并映射成功之后

策略：

- 关闭原始 CSV fd
- 运行期不再直接读取原始 CSV
- 可选：对原始 CSV 执行 `posix_fadvise(..., DONTNEED)`

### 11.2 pipeline trace 文件

原始文件：

- `trace.log`
- `trace_index.json`

最后热路径使用时机：

- trace sidecar 构建完成并映射成功之后

策略：

- 关闭原始 trace fd
- 运行期不再直接顺扫 `trace.log`
- 运行期不再主用 `trace_index.json`
- pipeline master 回收时：
  - `munmap`
  - 关闭 sidecar fd
  - 可选：对原始 trace 文件做 `DONTNEED`

### 11.3 注意

- “关闭文件句柄”不等于“释放解析后的 Python 大对象”
- 必须避免在 worker 中构造整份 `dict/list` 镜像
- 核心目标是“少构造对象 + 用 mmap 查询”，不是仅优化 fd 生命周期

## 12. IPC 与状态文件

### 12.1 Global AST Master

目录：

- `<runtime_root>/ipc/`
- `<runtime_root>/shared_ast/`
- `<runtime_root>/meta/`

文件：

- `global_ast_master.sock`
- `global_ast_master.pid`
- `global_ast_master.state.json`
- `shared_ast/ast.header.json`

### 12.2 Pipeline Trace Master

目录：

- `<run_dir>/ipc/`
- `<run_dir>/shared_trace/`
- `<run_dir>/meta/`

文件：

- `pipeline_trace_master.sock`
- `pipeline_trace_master.pid`
- `pipeline_trace_master.state.json`
- `shared_trace/trace.header.json`

### 12.3 环境变量

新增：

- `SYMEX_SHARED_MEMORY_ENABLED=1`
- `SYMEX_GLOBAL_AST_MASTER_SOCK=<path>`
- `SYMEX_PIPELINE_TRACE_MASTER_SOCK=<path>`
- `SYMEX_PIPELINE_RUN_DIR=<run_dir>`
- `SYMEX_PIPELINE_OWNER_PID=<pid>`
- `SYMEX_SHARED_MODE=master_worker`

保留：

- `WC_TOKEN_POOL_DIR`
- `WC_TOKEN_KIND`
- 其它现有 symex / witcher 环境变量

### 12.4 共享日志

全局共享日志目录：

- `<runtime_root>/shared_ast/logs/`
- `<runtime_root>/meta/global_ast_master.state.json`

pipeline 级共享日志目录：

- `<run_dir>/shared_trace/logs/`
- `<run_dir>/meta/pipeline_trace_master.state.json`

第一阶段 provider 抽象层日志目录：

- `<test/seq_*/shared_mem/logs/`
- `<test/seq_*/shared_mem/bootstrap_state.json`
- `<test/seq_*/shared_mem/provider_state.json`
- `<test/seq_*/shared_mem/provider_failure.json`

日志必须至少包含：

- 当前 provider/mode
- 是否启用共享
- 输入文件路径
- 共享数据 attach/build 状态
- 出错阶段
- 失败原因

## 13. 代码改造清单

### 13.1 新增目录

- `symex/shared_mem/`

建议文件：

- `__init__.py`
- `common.py`
- `uds.py`
- `fd_transfer.py`
- `shared_types.py`
- `ast_sidecar_builder.py`
- `trace_sidecar_builder.py`
- `ast_store.py`
- `trace_store.py`
- `global_ast_master.py`
- `pipeline_trace_master.py`
- `analyze_worker.py`
- `analyze_job_protocol.py`
- `analyze_core_adapter.py`
- `lifecycle.py`

### 13.2 需要修改的现有文件

- `symex/main.py`
  - 启动/停止 Global AST Master
  - 在 daemon `finally` 中收口全局 master
- `symex/hybrid_io/daemon_token_loop.py`
  - 启动 pipeline session 前准备 pipeline master
  - 停止时联动 pipeline master 回收
- `symex/branch_selector/pipeline.py`
  - attach pipeline master
  - 改 analyze 提交流程
  - 保持 semaphore 与 token 逻辑
- `symex/analyze_if_line.py`
  - 抽离 analyze 核心逻辑
  - 保留 CLI fallback
  - 新增 worker 执行入口
- `symex/utils/cpg_utils/graph_mapping.py`
  - 保留旧 API
  - 新增共享 store provider
- `symex/utils/cpg_utils/trace_index.py`
  - 保留旧 API
  - 新增 sidecar builder / loader 适配层
- `witcher/witcher/symex_launcher.py`
  - 仅在需要时补充状态透传与日志，不改变 stop 语义

## 14. 实施阶段

### 阶段 1：抽象共享数据访问层

目标：

- 不先改进程模型，先把“从文件读”与“从共享 store 读”抽象分离

输出：

- `AnalyzeContextProvider`
- `AstStoreProvider`
- `TraceStoreProvider`

验收：

- 旧路径行为不变
- 新 provider 接口完成

### 阶段 2：实现 Global AST Master

目标：

- sidecar 化并共享 AST 数据

输出：

- AST sidecar builder
- Global AST Master
- AST store attach 逻辑

验收：

- 多个 pipeline 不再直接读取 `nodes.csv/rels.csv`
- AST 共享 attach 成功
- fallback 可用

### 阶段 3：实现 Pipeline Trace Master

目标：

- sidecar 化并共享单 pipeline 的 trace 数据

输出：

- trace sidecar builder
- pipeline-local master
- trace attach 逻辑

验收：

- 同一 pipeline 内 analyze 不再顺扫 `trace.log`
- 不同 pipeline 之间 trace 数据隔离

### 阶段 4：Analyze Worker Pool

目标：

- 用固定 worker 池替换“一次 seq 一个 analyze 进程”

输出：

- worker entrypoint
- pipeline -> master job 提交流程
- 结果回传

验收：

- `max_analyze_concurrency` 语义保持
- `max_analyze_procs` 语义保持
- 输出结果与旧模式兼容

### 阶段 5：清理与观测

目标：

- 生命周期、清理、统计、泄漏防护全部补齐

输出：

- state 文件
- metrics / debug log
- orphan 回收
- stop 流程联动

验收：

- Witcher 停止 symex 后全局 master 正确退出
- pipeline 结束后局部 master 正确退出
- 无残留 socket/pid/state/worker

## 15. 回退策略

以下任一情况必须回退旧实现：

- 非 Linux
- sidecar builder 失败
- master 启动失败
- socket attach 失败
- fd 传递失败
- worker 池初始化失败
- 数据校验失败

回退要求：

- 记录明确日志
- 不影响当前 fuzz / symex 主流程继续运行
- 回退路径仍走现有 `pipeline.py -> analyze_if_line.py` 逻辑

## 16. 兼容性与不变项

必须保持不变：

- `analysis_output_<seq>.json` 结构
- 现有 `test/seq_<seq>/...` 输出布局
- token pool 文件格式与语义
- Witcher 的 `stop_symex()` 停止语义
- 非 Linux 平台行为

允许改变：

- analyze 子进程的具体启动方式
- `pipeline.py` 与 analyze 之间的通信方式
- AST / trace 的内部存储格式
- sidecar 与 socket 的新增目录结构

## 17. 实现时禁止事项

- 不要让不同 pipeline 共享 trace sidecar
- 不要让 analyze worker 再直接 `load_nodes/load_ast_edges/json.load(trace_index)`
- 不要改变现有三层并发限制的语义
- 不要把清理只依赖正常退出回调，必须做 pid 存活探测
- 不要在 Linux 共享路径失败时直接中断主流程，必须有 fallback

## 18. 第一轮实现的最小成功标准

- Linux 下可启动 Global AST Master
- 每个 pipeline 可启动自己的 Pipeline Trace Master
- 同一 pipeline 内 analyze worker 能复用共享 AST + trace
- `pipeline.py` 不再直接起 `analyze_if_line.py` 一次性短进程
- Witcher 结束 symex 时，全局 master 能被正确回收
- pipeline 及其 worker 结束后，局部 master 能被正确回收
- 旧输出结果与现有流程兼容
