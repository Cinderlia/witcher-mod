# Debug Session: login-cookie-divergence

Status: OPEN

## Problem
- post_login_followup 显示 cookie 有效。
- fuzz 运行时与 trace 运行时都被重定向到 wp-login.php。
- 需要对比三处使用登录状态逻辑的差异，找出后续登录失败原因。

## Hypotheses
1. post_login_followup 与 fuzz/trace 使用的 CGI 环境变量不同，尤其是 HTTP_HOST、SERVER_NAME、SCRIPT_NAME、REQUEST_URI，导致 WordPress 计算登录态上下文不同。
2. post_login_followup 使用的请求输入格式与 fuzz/trace 不同，cookie / GET / POST / headers 的拼接方式不同，导致目标脚本实际接收到的数据不同。
3. fuzz 运行时通过 seed 或运行脚本覆盖了登录相关 cookie 或 host 相关变量，导致 fresh_login 捕获的 cookie 在后续执行中被污染或覆盖。
4. WordPress 重定向中的 redirect_to 构造依赖某个缺失或错误的 SERVER/HTTP 变量，post_login_followup 没触发该路径，而 fuzz/trace 触发了。
5. 登录后的验证脚本 edit.php 与实际 fuzz/trace 访问脚本对权限或 nonce 要求不同，但当前 302 现象的直接原因仍是运行环境差异而非 cookie 本身失效。

## Evidence Plan
- 对比 _cgi_followup_check、fuzz 启动脚本环境、run_trace_with_seed.sh 的输入与环境。
- 添加最小化埋点，记录三处请求在真正执行 php-cgi 前的关键环境和 stdin 载荷摘要。
- 基于日志确认是否是 host/server/request 变量差异或输入载荷差异。

## Progress
- 已确认 post_login_followup 成功时 `REQUEST_URI` 为空，而 trace/fuzz 链路很可能被下游设置成 `SCRIPT`。
- 已在 trace 环境生成处增加 `REQUEST_URI` 传递，并在未显式提供时回退到 `SCRIPT_NAME`，其次回退到 `SCRIPT_FILENAME`。
- 审计确认：trace 脚本会先 source `trace_env_exports.sh`，随后直接以当前 shell 环境执行 `"{php_cgi_binary}"`，因此 `REQUEST_URI=/wordpress/wp-admin/edit.php` 确实会传入 php-cgi，除非 php-cgi 内部或其 preload 库再次改写。
- 审计确认：symex trace 调用的是配置里的 `afl_inst_interpreter_binary`（当前输出为 `/phpsrc/sapi/cgi/php-cgi`），不经过 `zend_witcher_trace.c`。
- 重新对比后，当前更重要的差异不是 redirect_to 指向，而是 followup 与 trace 在请求方法、QUERY_STRING、预加载相关环境（LD_PRELOAD/AFL_PRELOAD/WC_INSTRUMENTATION/NO_WC_EXTRA/STRICT 等）上可能不同，这些差异更可能影响登录态维持。
- 最新日志显示两边大部分环境已对齐，最显著差异是 `post_login_followup` 用 `METHOD=GET` 且 `REQUEST_METHOD` 为空，而 trace 用 `METHOD=POST` 且 `REQUEST_METHOD=POST`。
- 另一个可疑点是 seed 本身可能不携带完整登录 cookie；现已扩展 `loginSessionCookie` 支持列表形式，允许把多个登录 cookie 键重新注入 seed。
- 已补充调试输出，下一轮重点比较方法差异影响，并验证多 cookie 注入后 seed 是否维持登录态。
