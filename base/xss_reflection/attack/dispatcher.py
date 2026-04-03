from typing import Optional

from . import html_text, attr_value, attr_name, js_context, url_context, comment_context, tag_name


def get_handler(context_type: str):
    if context_type == "text":
        return html_text
    if context_type == "attr_value":
        return attr_value
    if context_type == "attr_name":
        return attr_name
    if context_type == "script":
        return js_context
    if context_type == "url":
        return url_context
    if context_type == "comment":
        return comment_context
    if context_type == "tag":
        return tag_name
    return None
