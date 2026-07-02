# Symex Hybrid IO

`prepare_symex_inputs.py` 用于把 symex 需要的输入从 Witcher/AFL 运行目录中提取并整理。

## 输入来源

- `AST/*.csv`：位于 `witcher_config.json` 同级目录下的 `AST` 文件夹
- AFL 启动脚本：`<work_dir>/fuzz-*.sh`
- AFL seeds：`<work_dir>/fuzzer-*/queue/id:*`
- 总覆盖率：`/dev/shm/coverages/*.cc.json`（按 `enable_cc.php` 规则从 `SCRIPT_FILENAME` 推导）

## 输出目录

输出会统一放在 `<work_dir>/symex_runtime/`，避免和 AFL 原始目录混杂：

- `ast_inputs/`：复制的 CSV
- `commands/`：提取后的命令与 trace 运行脚本
- `commands/test_command.txt`：提取后的关键 export（避免非 UTF-8 locale 下文件名编码问题）
- `coverage/`：复制的 `.cc.json`
- `seeds/raw/`：原始 seed（二进制）
- `seeds/text/`：解析后的 seed（COOKIE/GET/POST）
- `traces/`：预留给 trace.log
- `meta/prepare_report.json`：提取报告

## 使用方式

```bash
python witcher/symex/hybrid_io/prepare_symex_inputs.py \
  --config /path/to/witcher_config.json \
  --work-dir /path/to/work
```
