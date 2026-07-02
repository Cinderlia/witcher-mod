<?php
$do_cc = true;
$WC_CC_DEBUG_ENABLED = false;
$WC_CC_ROUTE_PROBE_ENABLED = true;
$WC_CC_STATS_LOG_ENABLED = false;

if (!function_exists('wc_cc_dbg')) {
    function wc_cc_dbg($msg) {
        global $WC_CC_DEBUG_ENABLED;
        if (!$WC_CC_DEBUG_ENABLED) {
            return;
        }
        $fp = "/tmp/enable_cc_debug.log";
        $ts = date('c');
        $pid = function_exists('getmypid') ? strval(getmypid()) : "0";
        $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        $script = isset($_SERVER['SCRIPT_FILENAME']) ? $_SERVER['SCRIPT_FILENAME'] : '';
        $line = $ts . " pid=" . $pid . " uri=" . $uri . " script=" . $script . " msg=" . strval($msg) . "\n";
        @file_put_contents($fp, $line, FILE_APPEND);
    }
}

if (!function_exists('wc_trace_session_capture_enabled')) {
    function wc_trace_session_capture_enabled() {
        $opcode_trace = getenv('OPCODE_TRACE');
        $capture_filename = getenv('WC_TRACE_SESSION_CAPTURE_FILENAME');
        return is_string($opcode_trace) && $opcode_trace !== '' && is_string($capture_filename) && $capture_filename !== '';
    }
}

if (!function_exists('wc_trace_session_capture_filename')) {
    function wc_trace_session_capture_filename() {
        $raw = getenv('WC_TRACE_SESSION_CAPTURE_FILENAME');
        if (!is_string($raw) || $raw === '') {
            return '';
        }
        $name = basename($raw);
        if ($name === '' || $name === '.' || $name === '..') {
            return '';
        }
        return preg_replace('/[^A-Za-z0-9._-]/', '_', $name);
    }
}

if (!function_exists('wc_trace_session_capture_path')) {
    function wc_trace_session_capture_path() {
        $capture_filename = wc_trace_session_capture_filename();
        if (!is_string($capture_filename) || $capture_filename === '') {
            return '';
        }
        $tmp_dir = function_exists('sys_get_temp_dir') ? sys_get_temp_dir() : '/tmp';
        $base_dir = rtrim($tmp_dir, "/\\") . DIRECTORY_SEPARATOR . 'wc_session_trace';
        return $base_dir . DIRECTORY_SEPARATOR . $capture_filename;
    }
}

if (!function_exists('wc_trace_session_json_safe')) {
    function wc_trace_session_json_safe($value, $depth = 0) {
        if ($depth >= 8) {
            return '<DEPTH_LIMIT>';
        }
        if (is_null($value) || is_bool($value) || is_int($value) || is_float($value) || is_string($value)) {
            return $value;
        }
        if (is_array($value)) {
            $out = [];
            foreach ($value as $k => $v) {
                $key = is_int($k) ? $k : strval($k);
                $out[$key] = wc_trace_session_json_safe($v, $depth + 1);
            }
            return $out;
        }
        if (is_object($value)) {
            return [
                '__class__' => get_class($value),
                '__value__' => wc_trace_session_json_safe(get_object_vars($value), $depth + 1),
            ];
        }
        return strval($value);
    }
}

if (!function_exists('wc_trace_session_write_json')) {
    function wc_trace_session_write_json($out_path, $payload) {
        if (!is_string($out_path) || $out_path === '') {
            return false;
        }
        $dir = dirname($out_path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }
        if (!is_dir($dir) || !is_writable($dir)) {
            return false;
        }
        $encoded_payload = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        if ($encoded_payload === false) {
            return false;
        }
        $tmp_path = $out_path . '.tmp';
        $written = @file_put_contents($tmp_path, $encoded_payload);
        if ($written === false) {
            return false;
        }
        if (!@rename($tmp_path, $out_path)) {
            @unlink($tmp_path);
            return false;
        }
        return true;
    }
}

if (!function_exists('wc_capture_trace_session')) {
    function wc_capture_trace_session() {
        if (!wc_trace_session_capture_enabled()) {
            return;
        }
        $out_path = wc_trace_session_capture_path();
        if ($out_path === '') {
            return;
        }

        $session_status_value = function_exists('session_status') ? @session_status() : null;
        $session_id_value = function_exists('session_id') ? strval(@session_id()) : '';
        $session_name_value = function_exists('session_name') ? strval(@session_name()) : '';
        $session_text = '';
        if (defined('PHP_SESSION_ACTIVE') && $session_status_value === PHP_SESSION_ACTIVE && function_exists('session_encode')) {
            $encoded = @session_encode();
            if (is_string($encoded)) {
                $session_text = $encoded;
            }
        }

        $cookie_session_id = '';
        if (!empty($_COOKIE) && is_array($_COOKIE) && isset($_COOKIE['PHPSESSID'])) {
            $cookie_session_id = strval($_COOKIE['PHPSESSID']);
        }

        $payload = [
            'captured_at' => date('c'),
            'pid' => function_exists('getmypid') ? intval(getmypid()) : 0,
            'user' => strval(getenv('USER')),
            'euid' => function_exists('posix_geteuid') ? @posix_geteuid() : null,
            'egid' => function_exists('posix_getegid') ? @posix_getegid() : null,
            'request_uri' => isset($_SERVER['REQUEST_URI']) ? strval($_SERVER['REQUEST_URI']) : '',
            'script_filename' => isset($_SERVER['SCRIPT_FILENAME']) ? strval($_SERVER['SCRIPT_FILENAME']) : '',
            'opcode_trace' => strval(getenv('OPCODE_TRACE')),
            'capture_filename' => strval(wc_trace_session_capture_filename()),
            'input_dir' => strval(getenv('WC_TRACE_INPUT_DIR')),
            'session_status' => $session_status_value,
            'session_name' => $session_name_value,
            'session_id' => $session_id_value,
            'cookie_phpsessid' => $cookie_session_id,
            'session_save_path' => strval(ini_get('session.save_path')),
            'session_serialize_handler' => strval(ini_get('session.serialize_handler')),
            'session_module_name' => function_exists('session_module_name') ? strval(@session_module_name()) : '',
            'session_text' => $session_text,
            'session_vars' => (isset($_SESSION) && is_array($_SESSION)) ? wc_trace_session_json_safe($_SESSION) : [],
            'capture_write_path' => $out_path,
        ];
        @wc_trace_session_write_json($out_path, $payload);
    }
}

if (isset($_SERVER['SCRIPT_FILENAME']) && !empty($_SERVER['SCRIPT_FILENAME'])) {
    $bn = basename($_SERVER['SCRIPT_FILENAME'], ".php");
    if ($bn == 'enable_cc.php' || $bn == 'export_cc.php'){
        $do_cc = false;
    }
}

// URL Routing Probe for Witcher
$probe_flag_file = '/tmp/witcher_route_probe.flag';

if ($WC_CC_ROUTE_PROBE_ENABLED && file_exists($probe_flag_file)) {
    $uri = $_SERVER['REQUEST_URI'] ?? '';
    $script = $_SERVER['SCRIPT_FILENAME'] ?? '';
    
    if ($uri && $script) {
        $app_dir = trim(file_get_contents($probe_flag_file)); // Now we only read app_dir from the flag file
        
        $script_normalized = str_replace('\\', '/', $script);
        $app_dir_normalized = str_replace('\\', '/', $app_dir);
        
        // In the test environment, /app and /var/www/html are symlinked and essentially the same directory.
        // We normalize both paths to use /var/www/html/ prefix for consistent comparison.
        if (strpos($app_dir_normalized, '/app/') === 0) {
            $app_dir_normalized = '/var/www/html/' . substr($app_dir_normalized, 5);
        }
        if (strpos($script_normalized, '/app/') === 0) {
            $script_normalized = '/var/www/html/' . substr($script_normalized, 5);
        }

        // Get the base name of the app directory to handle cases where the server 
        // root is different (e.g., /var/www/html/drupal-7 instead of /app/drupal-7)
        $app_base_name = basename(rtrim($app_dir_normalized, '/'));
        
        // Only log if app_dir is empty OR the script contains the application directory name
        // Also if app_dir is just '/app' or '/var/www', we should be more permissive
        $should_log = false;
        if (!$app_dir_normalized) {
            $should_log = true;
        } else if (strpos($script_normalized, $app_dir_normalized) === 0) {
            $should_log = true;
        } else if ($app_base_name !== 'app' && $app_base_name !== 'html' && strpos($script_normalized, '/' . $app_base_name . '/') !== false) {
            $should_log = true;
        } else if ($app_dir_normalized === '/var/www/html' && strpos($script_normalized, '/var/www/html/') === 0) {
            $should_log = true;
        }
        
        if ($should_log) {
            $probe_get = '';
            $probe_post = '';
            if (!empty($_GET) && is_array($_GET)) {
                $probe_get = http_build_query($_GET);
            }
            if (!empty($_POST) && is_array($_POST)) {
                $probe_post = http_build_query($_POST);
            }
            $mapping = [
                'uri' => parse_url($uri, PHP_URL_PATH),
                'script' => $script_normalized,
                'method' => $_SERVER['REQUEST_METHOD'] ?? '',
                'get' => $probe_get,
                'post' => $probe_post
            ];
            // Write to /tmp since www-data has permission
            $log_file = '/tmp/witcher_url_mapping.log';
            if (!is_dir('/tmp')) {
                @mkdir('/tmp', 0777, true);
            }
            @file_put_contents($log_file, json_encode($mapping) . "\n", FILE_APPEND);
        }
    }
}

if ($do_cc && wc_trace_session_capture_enabled()) {
    @register_shutdown_function('wc_capture_trace_session');
}

if (file_exists("/tmp/start_test.dat") && $do_cc) {

    date_default_timezone_set("America/Phoenix");
    $last_merge_err = "";
    
    $tarut = (isset($_SERVER['SCRIPT_FILENAME']) && !empty($_SERVER['SCRIPT_FILENAME'])) ? $_SERVER['SCRIPT_FILENAME'] : $_SERVER['REQUEST_URI'];
    $tarut_dirname = realpath(dirname($tarut));
    $tarut_dirname = str_replace("/","+",$tarut_dirname );
    $tarut_basename = basename($tarut, ".php");
    $tarut_name = $tarut_dirname . "+" . $tarut_basename;

    $parts = explode('+', $tarut_name);
    $names = [];
    foreach ($parts as $p) {
        if ($p !== '') $names[] = $p;
    }
    $first = isset($names[0]) ? $names[0] : 'root';
    $second = isset($names[1]) ? $names[1] : 'root';
    $group_key = "+" . $first . "+" . $second;

    $coverage_dpath = "/dev/shm/coverages/";
    if (!is_dir($coverage_dpath)) {
        @mkdir($coverage_dpath, 0777, true);
    }

    if ($WC_CC_DEBUG_ENABLED) {
        wc_cc_dbg("cc_enter do_cc=" . ($do_cc ? "1" : "0") . " start_test=1 cov_dir=" . $coverage_dpath . " cov_dir_exists=" . (is_dir($coverage_dpath) ? "1" : "0") . " xdebug_start=" . (function_exists('xdebug_start_code_coverage') ? "1" : "0") . " xdebug_get=" . (function_exists('xdebug_get_code_coverage') ? "1" : "0"));
    }
    if ($WC_CC_DEBUG_ENABLED) {
        wc_cc_dbg("cc_tarut tarut=" . strval($tarut) . " tarut_name=" . strval($tarut_name));
    }
    //echo "hidy-ho neighbor " . $tarut_dirname . "+" . $tarut_basename . "\n";

    xdebug_start_code_coverage(XDEBUG_CC_UNUSED | XDEBUG_CC_DEAD_CODE);
    function get(&$var, $default=null) {
        return isset($var) ? $var : $default;
    }
    function milliseconds() {
        $mt = explode(' ', microtime());
        return ((int)$mt[1]) * 1000 + ((int)round($mt[0] * 1000));
    }
    function cc_priority($v) {
        if ($v === 1) return 3;
        if ($v === -1) return 2;
        if ($v === -2) return 1;
        return 0;
    }
    function merge_cc($base, $delta) {
        if (!is_array($base)) $base = [];
        if (!is_array($delta)) $delta = [];
        foreach ($delta as $file => $lines) {
            if (!is_array($lines)) {
                continue;
            }
            if (!isset($base[$file]) || !is_array($base[$file])) {
                $base[$file] = $lines;
                continue;
            }
            foreach ($lines as $ln => $val) {
                if (!isset($base[$file][$ln])) {
                    $base[$file][$ln] = $val;
                } else {
                    $cur = $base[$file][$ln];
                    $base[$file][$ln] = cc_priority($val) >= cc_priority($cur) ? $val : $cur;
                }
            }
        }
        return $base;
    }
    function merge_group_cc($groupFPath, $cur_cc_jdata) {
        global $last_merge_err;
        $fp = fopen($groupFPath, 'c+');
        if ($fp === false) {
            $last_merge_err = "open_fail";
            wc_cc_dbg("merge_group_cc open_fail path=" . strval($groupFPath));
            return false;
        }
        if (!flock($fp, LOCK_EX)) {
            $last_merge_err = "lock_fail";
            wc_cc_dbg("merge_group_cc lock_fail path=" . strval($groupFPath));
            fclose($fp);
            return false;
        }
        $existing = '';
        rewind($fp);
        while (!feof($fp)) {
            $existing .= fread($fp, 8192);
        }
        $existingArr = json_decode($existing, true);
        if (!is_array($existingArr)) $existingArr = [];
        $merged = merge_cc($existingArr, $cur_cc_jdata);
        $encoded = json_encode($merged);
        if ($encoded === false) {
            $last_merge_err = "encode_fail";
            wc_cc_dbg("merge_group_cc encode_fail path=" . strval($groupFPath));
            flock($fp, LOCK_UN);
            fclose($fp);
            return false;
        }
        if (!ftruncate($fp, 0)) {
            $last_merge_err = "truncate_fail";
            wc_cc_dbg("merge_group_cc truncate_fail path=" . strval($groupFPath));
            flock($fp, LOCK_UN);
            fclose($fp);
            return false;
        }
        if (!rewind($fp)) {
            $last_merge_err = "rewind_fail";
            wc_cc_dbg("merge_group_cc rewind_fail path=" . strval($groupFPath));
            flock($fp, LOCK_UN);
            fclose($fp);
            return false;
        }
        $written = fwrite($fp, $encoded);
        if ($written === false || $written < strlen($encoded)) {
            $last_merge_err = "write_fail";
            wc_cc_dbg("merge_group_cc write_fail path=" . strval($groupFPath));
            flock($fp, LOCK_UN);
            fclose($fp);
            return false;
        }
        if (!fflush($fp)) {
            $last_merge_err = "flush_fail";
            wc_cc_dbg("merge_group_cc flush_fail path=" . strval($groupFPath));
            flock($fp, LOCK_UN);
            fclose($fp);
            return false;
        }
        flock($fp, LOCK_UN);
        fclose($fp);
        return true;
    }
    function group_key_from_tarut_name($tarut_name) {
        $parts = explode('+', $tarut_name);
        $names = [];
        foreach ($parts as $p) {
            if ($p !== '') $names[] = $p;
        }
        $first = isset($names[0]) ? $names[0] : 'root';
        $second = isset($names[1]) ? $names[1] : 'root';
        return "+" . $first . "+" . $second;
    }
    function get_group_cc_fpath($coverage_dpath, $tarut_name) {
        return $coverage_dpath . group_key_from_tarut_name($tarut_name) . ".cc.json";
    }
    function get_log_fpath($tarut_name) {
        $log_dir = "/tmp/enable/";
        if (!is_dir($log_dir)) {
            mkdir($log_dir, 0777, true);
        }
        return $log_dir . group_key_from_tarut_name($tarut_name) . ".json";
    }
    function update_log($log_fpath, $delta) {
        $fp = fopen($log_fpath, 'c+');
        if ($fp === false) {
            return false;
        }
        if (!flock($fp, LOCK_EX)) {
            fclose($fp);
            return false;
        }
        $existing = '';
        rewind($fp);
        while (!feof($fp)) {
            $existing .= fread($fp, 8192);
        }
        $arr = json_decode($existing, true);
        if (!is_array($arr)) $arr = [];
        foreach ($delta as $k => $v) {
            if ($k === 'last_ts' || $k === 'last_files' || $k === 'last_bytes' || $k === 'last_merge_err' || $k === 'last_merge_err_ts') {
                $arr[$k] = $v;
                continue;
            }
            $cur = isset($arr[$k]) ? $arr[$k] : 0;
            $arr[$k] = $cur + $v;
        }
        $encoded = json_encode($arr);
        if ($encoded === false) {
            flock($fp, LOCK_UN);
            fclose($fp);
            return false;
        }
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, $encoded);
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
        return true;
    }
    function end_coverage()
    {
        global $tarut_name;
        global $coverage_dpath;
        global $last_merge_err;

        $coverageName = $coverage_dpath . $tarut_name . "_" . strval(milliseconds()) . ".cc";
	    $jsonCoverageFPath = $coverageName . ".json";
        if ($GLOBALS["WC_CC_DEBUG_ENABLED"]) {
            wc_cc_dbg("end_coverage start json=" . strval($jsonCoverageFPath));
        }

        try {
            xdebug_stop_code_coverage(false);

            $cur_cc_jdata = xdebug_get_code_coverage();
            $json_data = json_encode($cur_cc_jdata);
            if ($json_data === false) {
                $log_fpath = get_log_fpath($tarut_name);
                if ($GLOBALS["WC_CC_STATS_LOG_ENABLED"]) {
                    update_log($log_fpath, [
                        "total" => 1,
                        "json_fail" => 1,
                        "last_ts" => time()
                    ]);
                }
                if ($GLOBALS["WC_CC_DEBUG_ENABLED"]) {
                    wc_cc_dbg("end_coverage json_encode_fail log=" . strval($log_fpath));
                }
                error_log("[Witcher CC] Failed to json_encode coverage data for $tarut_name. Error: " . json_last_error_msg());
                return;
            }
            $single_ok = file_put_contents($jsonCoverageFPath, $json_data);
            if ($single_ok === false) {
                error_log("[Witcher CC] Failed to write coverage file: $jsonCoverageFPath");
            }
            $log_fpath = get_log_fpath($tarut_name);
            /*
            $groupFPath = get_group_cc_fpath($coverage_dpath, $tarut_name);
            $merged_ok = merge_group_cc($groupFPath, $cur_cc_jdata);
            $merge_err = $merged_ok ? "" : ($last_merge_err !== "" ? $last_merge_err : "unknown");
            update_log($log_fpath, [
                "total" => 1,
                "single_write_fail" => $single_ok === false ? 1 : 0,
                "merge_ok" => $merged_ok ? 1 : 0,
                "merge_fail" => $merged_ok ? 0 : 1,
                "empty_cur" => empty($cur_cc_jdata) ? 1 : 0,
                "last_ts" => time(),
                "last_files" => is_array($cur_cc_jdata) ? count($cur_cc_jdata) : 0,
                "last_bytes" => strlen($json_data),
                "last_merge_err" => $merge_err,
                "last_merge_err_ts" => $merged_ok ? 0 : time()
            ]);
            wc_cc_dbg("end_coverage done single_ok=" . ($single_ok === false ? "0" : "1") . " group=" . strval($groupFPath) . " merged_ok=" . ($merged_ok ? "1" : "0") . " merge_err=" . strval($merge_err) . " files=" . (is_array($cur_cc_jdata) ? strval(count($cur_cc_jdata)) : "0"));
            */
            if ($GLOBALS["WC_CC_STATS_LOG_ENABLED"]) {
                update_log($log_fpath, [
                    "total" => 1,
                    "single_write_fail" => $single_ok === false ? 1 : 0,
                    "empty_cur" => empty($cur_cc_jdata) ? 1 : 0,
                    "last_ts" => time(),
                    "last_files" => is_array($cur_cc_jdata) ? count($cur_cc_jdata) : 0,
                    "last_bytes" => strlen($json_data)
                ]);
            }
            if ($GLOBALS["WC_CC_DEBUG_ENABLED"]) {
                wc_cc_dbg("end_coverage done single_ok=" . ($single_ok === false ? "0" : "1") . " files=" . (is_array($cur_cc_jdata) ? strval(count($cur_cc_jdata)) : "0"));
            }

        } catch (Exception $ex) {
            file_put_contents($coverage_dpath."exceptions.log", $ex, FILE_APPEND);
            if ($GLOBALS["WC_CC_DEBUG_ENABLED"]) {
                wc_cc_dbg("end_coverage exception=" . strval($ex));
            }
        } finally {

        }
    }

    class coverage_dumper
    {
        function __destruct()
        {
            try {
                end_coverage();
            } catch (Exception $ex) {
                echo str($ex);
            }
        }
    }

    $_coverage_dumper = new coverage_dumper();
}
