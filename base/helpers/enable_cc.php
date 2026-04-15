<?php
$do_cc = true;
$WC_CC_DEBUG_ENABLED = false;
$WC_CC_ROUTE_PROBE_ENABLED = false;
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
        
        // Get the base name of the app directory to handle cases where the server 
        // root is different (e.g., /var/www/html/drupal-7 instead of /app/drupal-7)
        $app_base_name = basename(rtrim($app_dir, '/'));
        
        // Only log if app_dir is empty OR the script contains the application directory name
        // Also if app_dir is just '/app' or '/var/www', we should be more permissive
        $should_log = false;
        if (!$app_dir) {
            $should_log = true;
        } else if (strpos($script, $app_dir) === 0) {
            $should_log = true;
        } else if ($app_base_name !== 'app' && $app_base_name !== 'html' && strpos($script, '/' . $app_base_name . '/') !== false) {
            $should_log = true;
        } else if ($app_dir === '/app' && strpos($script, '/var/www/html/') === 0) {
            // Special case: Witcher often mounts /app but Apache serves from /var/www/html/
            $should_log = true;
        }
        
        if ($should_log) {
            $mapping = [
                'uri' => parse_url($uri, PHP_URL_PATH),
                'script' => $script
            ];
            // Write to /tmp since www-data has permission
            $log_file = '/tmp/witcher_url_mapping.log';
            file_put_contents($log_file, json_encode($mapping) . "\n", FILE_APPEND);
        }
    }
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

    $coverage_dpath = "/dev/shm/coverages/" . $group_key . "/";
    if (!is_dir($coverage_dpath)) {
        @mkdir($coverage_dpath, 0777, true);
    }
    if (!is_dir($coverage_dpath)) {
        $coverage_dpath = "/tmp/coverages/" . $group_key . "/";
        if (!is_dir($coverage_dpath)) {
            @mkdir($coverage_dpath, 0777, true);
        }
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
