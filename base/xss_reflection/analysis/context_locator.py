import re
from typing import List, NamedTuple, Optional, Tuple


class ContextHit(NamedTuple):
    context_type: str
    quote: Optional[str]
    attr_name: Optional[str]
    position: int
    snippet: str


class ContextLocator:
    def __init__(self, window: int = 120):
        self.window = window
        self.attr_re = re.compile(r'([a-zA-Z0-9:_-]+)\s*=\s*(".*?"|\'.*?\'|[^\s>]+)')
        self.url_attrs = {"href", "src", "action"}

    def locate(self, body: str, token: str) -> List[ContextHit]:
        hits = []
        for pos in self._find_positions(body, token):
            snippet = self._snippet(body, pos)
            context_type, quote, attr_name = self._classify(body, pos, token)
            hits.append(ContextHit(context_type=context_type, quote=quote, attr_name=attr_name, position=pos, snippet=snippet))
        return hits

    def _find_positions(self, body: str, token: str) -> List[int]:
        positions = []
        start = 0
        while True:
            idx = body.find(token, start)
            if idx == -1:
                break
            positions.append(idx)
            start = idx + len(token)
        return positions

    def _classify(self, body: str, pos: int, token: str) -> Tuple[str, Optional[str], Optional[str]]:
        if self._in_comment(body, pos):
            return "comment", None, None
        if self._in_script(body, pos):
            quote = self._script_quote(body, pos)
            return "script", quote, None
        tag = self._tag_at(body, pos)
        if tag:
            context_type, quote, attr_name = self._tag_context(tag, pos, token)
            return context_type, quote, attr_name
        return "text", None, None

    def _in_comment(self, body: str, pos: int) -> bool:
        start = body.rfind("<!--", 0, pos)
        end = body.rfind("-->", 0, pos)
        return start != -1 and (end == -1 or end < start)

    def _in_script(self, body: str, pos: int) -> bool:
        bounds = self._script_bounds(body, pos)
        return bounds is not None

    def _tag_at(self, body: str, pos: int) -> Optional[Tuple[int, int, str]]:
        lt = body.rfind("<", 0, pos)
        gt = body.rfind(">", 0, pos)
        if lt == -1 or (gt != -1 and gt > lt):
            return None
        end = body.find(">", lt)
        if end == -1:
            return None
        return lt, end, body[lt + 1:end]

    def _tag_context(self, tag: Tuple[int, int, str], pos: int, token: str) -> Tuple[str, Optional[str], Optional[str]]:
        lt, end, tag_body = tag
        rel = pos - (lt + 1)
        name_end = re.search(r"[\s/>]", tag_body)
        if name_end is None:
            eq_pos = tag_body.find("=")
            if eq_pos != -1:
                if rel <= eq_pos:
                    return "attr_name", None, None
                return "attr_value", None, None
            return "tag", None, None
        if rel <= name_end.start():
            eq_pos = tag_body.find("=")
            if eq_pos != -1 and rel <= eq_pos:
                return "attr_name", None, None
            return "tag", None, None

        for match in self.attr_re.finditer(tag_body):
            name = match.group(1)
            value = match.group(2)
            value_start = match.start(2)
            value_end = match.end(2)
            name_start = match.start(1)
            name_end = match.end(1)
            if name_start <= rel <= name_end:
                return "attr_name", None, name.lower()
            if value_start <= rel <= value_end:
                quote = None
                if value and value[0] in {"'", '"'}:
                    quote = value[0]
                if name.lower() in self.url_attrs:
                    return "url", quote, name.lower()
                return "attr_value", quote, name.lower()
        return "attr_value", None, None

    def _script_bounds(self, body: str, pos: int) -> Optional[Tuple[int, int]]:
        start = body.rfind("<script", 0, pos)
        if start == -1:
            return None
        start_end = body.find(">", start)
        if start_end == -1:
            return None
        end = body.find("</script", start_end)
        if end == -1:
            return None
        if not (start_end < pos < end):
            return None
        return start_end + 1, end

    def _script_quote(self, body: str, pos: int) -> Optional[str]:
        bounds = self._script_bounds(body, pos)
        if not bounds:
            return None
        start, end = bounds
        rel = pos - start
        script_text = body[start:end]
        state = self._js_state(script_text, rel)
        return state

    def _js_state(self, text: str, index: int) -> Optional[str]:
        in_single = False
        in_double = False
        in_template = False
        in_line = False
        in_block = False
        escape = False
        i = 0
        while i < index and i < len(text):
            ch = text[i]
            nxt = text[i + 1] if i + 1 < len(text) else ""
            if in_line:
                if ch == "\n":
                    in_line = False
            elif in_block:
                if ch == "*" and nxt == "/":
                    in_block = False
                    i += 1
            elif in_single:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == "'":
                    in_single = False
            elif in_double:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_double = False
            elif in_template:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == "`":
                    in_template = False
            else:
                if ch == "/" and nxt == "/":
                    in_line = True
                    i += 1
                elif ch == "/" and nxt == "*":
                    in_block = True
                    i += 1
                elif ch == "'":
                    in_single = True
                elif ch == '"':
                    in_double = True
                elif ch == "`":
                    in_template = True
            i += 1
        if in_single:
            return "'"
        if in_double:
            return '"'
        if in_template:
            return "`"
        return None

    def _snippet(self, body: str, pos: int) -> str:
        left = max(0, pos - self.window)
        right = min(len(body), pos + self.window)
        return body[left:right]
