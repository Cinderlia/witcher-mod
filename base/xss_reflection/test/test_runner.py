import sys
import os

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

from xss_reflection.analysis.context_locator import ContextLocator
from xss_reflection.attack import dispatcher
from xss_reflection.attack.common import WITCHER_MARKER


def assert_equal(actual, expected, message):
    if actual != expected:
        raise AssertionError(f"{message}: expected={expected} actual={actual}")


def test_context_classification():
    locator = ContextLocator()
    token = "witcher_xss_1234"
    cases = [
        ("text", f"<div>{token}</div>"),
        ("text", f"<div>abc {token} xyz</div>"),
        ("attr_value", f"<input value=\"{token}\">"),
        ("attr_value", f"<input value=\"abc {token} xyz\">"),
        ("attr_name", f"<{token}=\"value\">"),
        ("script", f"<script>var a=\"{token}\";</script>"),
        ("url", f"<a href=\"{token}\">x</a>"),
        ("comment", f"<!-- {token} -->"),
        ("tag", f"<{token}>"),
    ]
    for expected, html in cases:
        hits = locator.locate(html, token)
        if not hits:
            raise AssertionError(f"no hit for {expected}")
        assert_equal(hits[0].context_type, expected, f"context type {expected}")
    multi = f"<div>{token}</div><script>{token}</script>"
    multi_hits = locator.locate(multi, token)
    assert_equal(len(multi_hits), 2, "multi-hit count")
    types = sorted([h.context_type for h in multi_hits])
    assert_equal(types, ["script", "text"], "multi-hit types")


def test_breakout_detection():
    cases = [
        ("text", f"<script>{WITCHER_MARKER}</script>", "ok"),
        ("text", f"<div>{WITCHER_MARKER}</div>", "bad"),
        ("text", f"&lt;script&gt;{WITCHER_MARKER}&lt;/script&gt;", "bad"),
        ("text", f"&#60;script&#62;{WITCHER_MARKER}&#60;/script&#62;", "bad"),
        ("text", f"&#x3c;script&#x3e;{WITCHER_MARKER}&#x3c;/script&#x3e;", "bad"),
        ("attr_value", f"<img src=x onerror=alert({WITCHER_MARKER})>", "ok"),
        ("attr_value", f"<input value=\"{WITCHER_MARKER}\">", "bad"),
        ("attr_value", f"<input value=\"\" onerror=alert({WITCHER_MARKER}) x=\"\">", "bad"),
        ("attr_value", f"<input value='{WITCHER_MARKER}'>", "bad"),
        ("attr_value", f"<input value='' onerror=alert({WITCHER_MARKER}) x=''>", "bad"),
        ("attr_value", f"<img src=x onerror=\"{WITCHER_MARKER}\">", "bad"),
        ("attr_name", f"<img onerror=alert({WITCHER_MARKER})>", "ok"),
        ("attr_name", f"<img {WITCHER_MARKER}=\"x\">", "bad"),
        ("attr_name", f"<div onerror={WITCHER_MARKER}=\"test\">", "bad"),
        ("script", f"<script>var a=\"\";{WITCHER_MARKER};//\";</script>", "ok"),
        ("script", f"<script>var a=\"{WITCHER_MARKER}\";</script>", "bad"),
        ("script", f"<script>var a='{WITCHER_MARKER}';</script>", "bad"),
        ("script", f"<script>var a='';{WITCHER_MARKER};//';</script>", "ok"),
        ("script", f"<script>var a=`{WITCHER_MARKER}`;</script>", "bad"),
        ("script", f"<script>var a=\"<script>{WITCHER_MARKER}</script>\";</script>", "bad"),
        ("script", f"<script>//{WITCHER_MARKER}\n</script>", "bad"),
        ("url", f"<a href=\"javascript:alert({WITCHER_MARKER})\">x</a>", "ok"),
        ("url", f"<a href=\"JaVaScRiPt:alert({WITCHER_MARKER})\">x</a>", "ok"),
        ("url", f"<a href=\"data:text/html,<script>{WITCHER_MARKER}</script>\">x</a>", "ok"),
        ("url", f"<a href=\"data:{WITCHER_MARKER}\">x</a>", "bad"),
        ("url", f"<a href=\"vbscript:msgbox({WITCHER_MARKER})\">x</a>", "ok"),
        ("url", f"<a href=\"javascript:var a='{WITCHER_MARKER}'\">x</a>", "ok"),
        ("url", f"<a href=\"javascript:{WITCHER_MARKER}\">x</a>", "bad"),
        ("url", f"<a href=\"{WITCHER_MARKER}\">x</a>", "bad"),
        ("comment", f"<!-- --><script>{WITCHER_MARKER}</script> -->", "ok"),
        ("comment", f"<!-- --!><script>{WITCHER_MARKER}</script> -->", "ok"),
        ("comment", f"<!-- {WITCHER_MARKER} -->", "bad"),
        ("tag", f"<script>{WITCHER_MARKER}</script>", "ok"),
        ("tag", f"<{WITCHER_MARKER}>", "bad"),
    ]
    for context_type, html, expectation in cases:
        handler = dispatcher.get_handler(context_type)
        if handler is None:
            raise AssertionError(f"handler missing {context_type}")
        actual = handler.is_success(html)
        expected = expectation == "ok"
        assert_equal(actual, expected, f"breakout {context_type}")


def main():
    test_context_classification()
    test_breakout_detection()
    print("xss_reflection tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
