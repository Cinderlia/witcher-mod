<?php
header("Content-Type: text/html");

// 安全获取参数
function p($name) {
    return isset($_GET[$name]) ? $_GET[$name] : '';
}

$params = [
    "cmd1","cmd2","cmd3","cmd4","cmd5",
    "cmd6","cmd7","cmd8","cmd9","cmd10"
];


echo "<h2>Command Injection Test</h2>";

foreach ($params as $p) {
    echo "<a href='?{$p}=test'>GET {$p}</a><br>";
}

echo "<hr>";

foreach ($params as $p) {
    echo "<form method='GET'>";
    echo "<input name='{$p}' value='test'>";
    echo "<input type='submit' value='submit {$p}'>";
    echo "</form>";
}

echo "<script>";
foreach ($params as $p) {
    echo "fetch('?{$p}=auto');";
}
echo "</script>";

echo "<hr><pre>";


if ($c = p("cmd1")) {
    echo "[cmd1]\n";
    system("ls " . $c);
}

if ($c = p("cmd2")) {
    echo "[cmd2]\n";
    system("ls '" . $c . "'");
}

if ($c = p("cmd3")) {
    echo "[cmd3]\n";
    system("ls \"" . $c . "\"");
}

if ($c = p("cmd4")) {
    echo "[cmd4]\n";
    echo `echo test && ls $c`;
}

if ($c = p("cmd5")) {
    echo "[cmd5]\n";
    exec("cat " . $c, $out);
    print_r($out);
}

if ($c = p("cmd6")) {
    echo "[cmd6]\n";
    passthru("ping -c 1 " . $c);
}

if ($c = p("cmd7")) {
    echo "[cmd7]\n";
    system("cat /tmp/" . $c);
}

if ($c = p("cmd8")) {
    echo "[cmd8]\n";
    $c = str_replace(";", "", $c);
    system("ls " . $c);
}

if (isset($_GET["cmd9"])) {
    echo "[cmd9]\n";
    $c = $_GET["cmd9"];
    system("echo " . $c);
}

if ($c = p("cmd10")) {
    echo "[cmd10]\n";
    system("grep 'test' /var/log/" . $c);
}

echo "</pre>";
?>