<?php
$do_cc = true;

if (isset($_SERVER['SCRIPT_FILENAME']) && !empty($_SERVER['SCRIPT_FILENAME'])) {
    $bn = basename($_SERVER['SCRIPT_FILENAME'], ".php");
    if ($bn == 'enable_cc.php' || $bn == 'export_cc.php'){
        $do_cc = false;
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
            return false;
        }
        if (!flock($fp, LOCK_EX)) {
            $last_merge_err = "lock_fail";
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
            flock($fp, LOCK_UN);
            fclose($fp);
            return false;
        }
        if (!ftruncate($fp, 0)) {
            $last_merge_err = "truncate_fail";
            flock($fp, LOCK_UN);
            fclose($fp);
            return false;
        }
        if (!rewind($fp)) {
            $last_merge_err = "rewind_fail";
            flock($fp, LOCK_UN);
            fclose($fp);
            return false;
        }
        $written = fwrite($fp, $encoded);
        if ($written === false || $written < strlen($encoded)) {
            $last_merge_err = "write_fail";
            flock($fp, LOCK_UN);
            fclose($fp);
            return false;
        }
        if (!fflush($fp)) {
            $last_merge_err = "flush_fail";
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

        $pid = function_exists("getmypid") ? strval(getmypid()) : "0";
        $coverageName = $coverage_dpath . $tarut_name . "_" . strval(milliseconds()) . "_" . $pid . ".cc";
	    $jsonCoverageFPath = $coverageName . ".json";

        try {
            xdebug_stop_code_coverage(false);

            $cur_cc_jdata = xdebug_get_code_coverage();
            $json_data = json_encode($cur_cc_jdata);
            if ($json_data === false) {
                $log_fpath = get_log_fpath($tarut_name);
                update_log($log_fpath, [
                    "total" => 1,
                    "json_fail" => 1,
                    "last_ts" => time()
                ]);
                error_log("[Witcher CC] Failed to json_encode coverage data for $tarut_name. Error: " . json_last_error_msg());
                return;
            }
            $single_ok = file_put_contents($jsonCoverageFPath, $json_data);
            if ($single_ok === false) {
                error_log("[Witcher CC] Failed to write coverage file: $jsonCoverageFPath");
            }
            $groupFPath = get_group_cc_fpath($coverage_dpath, $tarut_name);
            $merged_ok = merge_group_cc($groupFPath, $cur_cc_jdata);
            $log_fpath = get_log_fpath($tarut_name);
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

        } catch (Exception $ex) {
	        echo "ERROR encountered " . $ex . "\n";
            file_put_contents($coverage_dpath."exceptions.log", $ex, FILE_APPEND);
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
