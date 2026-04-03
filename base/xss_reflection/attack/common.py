WITCHER_MARKER = "WITCHER"


def html_unescape(value: str) -> str:
    return (
        value.replace("&lt;", "<")
        .replace("&#60;", "<")
        .replace("&#x3c;", "<")
        .replace("&#x3C;", "<")
        .replace("&gt;", ">")
        .replace("&#62;", ">")
        .replace("&#x3e;", ">")
        .replace("&#x3E;", ">")
        .replace("&quot;", '"')
        .replace("&#34;", '"')
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
    )
