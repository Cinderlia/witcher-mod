<?php

function wc_render_session_read_stdin() {
    $raw = file_get_contents('php://stdin');
    return is_string($raw) ? $raw : '';
}

function wc_render_session_json_response($payload) {
    $is_cli = (PHP_SAPI === 'cli');
    if (!$is_cli && !headers_sent()) {
        header('Content-Type: application/json');
    }
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function wc_render_session_files_dir($save_path) {
    $raw = is_string($save_path) ? trim($save_path) : '';
    if ($raw === '') {
        return '/tmp/php_sessions';
    }
    $parts = explode(';', $raw);
    $last = trim($parts[count($parts) - 1]);
    if ($last !== '') {
        return $last;
    }
    return $raw;
}

$raw = wc_render_session_read_stdin();
$obj = json_decode($raw, true);
if (!is_array($obj)) {
    wc_render_session_json_response([
        'ok' => false,
        'error' => 'invalid_json',
    ]);
}

$session_id = isset($obj['session_id']) ? strval($obj['session_id']) : '';
$session_name = isset($obj['session_name']) ? strval($obj['session_name']) : 'PHPSESSID';
$session_save_path = isset($obj['session_save_path']) ? strval($obj['session_save_path']) : '';
$session_vars = isset($obj['session_vars']) && is_array($obj['session_vars']) ? $obj['session_vars'] : [];

if ($session_id === '') {
    wc_render_session_json_response([
        'ok' => false,
        'error' => 'missing_session_id',
    ]);
}

if ($session_name === '') {
    $session_name = 'PHPSESSID';
}

$files_dir = wc_render_session_files_dir($session_save_path);
if ($files_dir === '') {
    $files_dir = '/tmp/php_sessions';
}

if (!is_dir($files_dir)) {
    @mkdir($files_dir, 0777, true);
}

@ini_set('session.save_handler', 'files');
@ini_set('session.save_path', $session_save_path !== '' ? $session_save_path : $files_dir);
@session_name($session_name);
@session_id($session_id);

$ok = @session_start();
if (!$ok) {
    wc_render_session_json_response([
        'ok' => false,
        'error' => 'session_start_failed',
        'session_id' => $session_id,
        'session_name' => $session_name,
    ]);
}

$_SESSION = $session_vars;
@session_write_close();

$session_file_path = rtrim($files_dir, "/\\") . DIRECTORY_SEPARATOR . 'sess_' . $session_id;

wc_render_session_json_response([
    'ok' => true,
    'session_id' => $session_id,
    'session_name' => $session_name,
    'session_file_path' => $session_file_path,
]);
