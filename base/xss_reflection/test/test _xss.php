<?php
// 获取所有参数（避免未定义 warning）
function g($k) {
    return isset($_GET[$k]) ? $_GET[$k] : "";
}

// 安全输出
function h($k) {
    return htmlspecialchars(g($k), ENT_QUOTES, 'UTF-8');
}

function js($k) {
    return json_encode(g($k), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
}

function url_safe($k) {
    $raw = g($k);
    $parts = parse_url($raw);
    if ($parts === false || !isset($parts["scheme"])) {
        return "";
    }
    $scheme = strtolower($parts["scheme"]);
    if ($scheme !== "http" && $scheme !== "https") {
        return "";
    }
    return htmlspecialchars($raw, ENT_QUOTES, 'UTF-8');
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>XSS Testbed</title>
</head>
<body>

<h1>XSS Test Page (for Witcher)</h1>

<!-- ================== HTML TEXT ================== -->
<h2>1. HTML Text Context</h2>

<p>Unsafe: <?php echo g("html_unsafe"); ?></p>
<p>Safe: <?php echo h("html_safe"); ?></p>

<!-- ================== ATTRIBUTE VALUE ================== -->
<h2>2. Attribute Value Context</h2>

<input value="<?php echo g("attr_unsafe"); ?>">
<br>
<input value="<?php echo h("attr_safe"); ?>">

<!-- ================== ATTRIBUTE NAME ================== -->
<h2>3. Attribute Name Context</h2>

<div <?php echo g("attrname_unsafe"); ?>="test">Unsafe attr name</div>
<div <?php echo h("attrname_safe"); ?>="test">Safe attr name</div>

<!-- ================== SCRIPT CONTEXT ================== -->
<h2>4. Script Context</h2>

<script>
var unsafe_js = "<?php echo g("js_unsafe"); ?>";
var safe_js = <?php echo js("js_safe"); ?>;
</script>

<!-- ================== URL / HREF ================== -->
<h2>5. URL Context</h2>

<a href="<?php echo g("url_unsafe"); ?>">Unsafe Link</a><br>
<a href="<?php echo url_safe("url_safe"); ?>">Safe Link</a>

<!-- ================== COMMENT CONTEXT ================== -->
<h2>6. Comment Context</h2>

<!-- <?php echo g("comment_unsafe"); ?> -->
<!-- <?php echo h("comment_safe"); ?> -->

<!-- ================== TAG STRUCTURE ================== -->
<h2>7. Tag Structure Context</h2>

<?php echo g("tag_unsafe"); ?>
<?php echo h("tag_safe"); ?>

<!-- ================== LINKS FOR CRAWLER ================== -->
<h2>Links (for crawler)</h2>

<ul>
    <li><a href="?html_unsafe=test">html_unsafe</a></li>
    <li><a href="?html_safe=test">html_safe</a></li>

    <li><a href="?attr_unsafe=test">attr_unsafe</a></li>
    <li><a href="?attr_safe=test">attr_safe</a></li>

    <li><a href="?attrname_unsafe=test">attrname_unsafe</a></li>
    <li><a href="?attrname_safe=test">attrname_safe</a></li>

    <li><a href="?js_unsafe=test">js_unsafe</a></li>
    <li><a href="?js_safe=test">js_safe</a></li>

    <li><a href="?url_unsafe=test">url_unsafe</a></li>
    <li><a href="?url_safe=test">url_safe</a></li>

    <li><a href="?comment_unsafe=test">comment_unsafe</a></li>
    <li><a href="?comment_safe=test">comment_safe</a></li>

    <li><a href="?tag_unsafe=test">tag_unsafe</a></li>
    <li><a href="?tag_safe=test">tag_safe</a></li>
</ul>

</body>
</html>
