"""Minimal HTTP clients for OpenAI-compatible and Anthropic-compatible chat APIs."""

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Union

from ..core.config import LLMConfig, load_llm_config


class OpenAIClient:
    """A lightweight OpenAI-compatible chat completion client (urllib-based)."""
    def __init__(self, base_url: str, api_key: str, default_model: Optional[str] = None, timeout_s: float = 60.0):
        self.base_url = (base_url or '').rstrip('/')
        self.api_key = api_key or ''
        self.default_model = default_model
        self.timeout_s = float(timeout_s)

    def create_chat_completion(
        self,
        *,
        messages: List[Dict[str, Any]],
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Call `/v1/chat/completions` and return the decoded JSON object."""
        use_model = model or self.default_model
        if not use_model:
            raise ValueError('missing model')
        if not self.api_key:
            raise ValueError('missing api_key')
        if not self.base_url:
            raise ValueError('missing base_url')

        payload: Dict[str, Any] = {
            'model': use_model,
            'messages': messages,
        }
        if temperature is not None:
            payload['temperature'] = float(temperature)
        if max_tokens is not None:
            payload['max_tokens'] = int(max_tokens)
        if isinstance(extra, dict) and extra:
            payload.update(extra)

        url = self.base_url + '/v1/chat/completions'
        req = urllib.request.Request(
            url=url,
            data=json.dumps(payload, ensure_ascii=False).encode('utf-8'),
            headers={
                'Authorization': 'Bearer ' + self.api_key,
                'Content-Type': 'application/json; charset=utf-8',
            },
            method='POST',
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                body = ''
            err = RuntimeError(f'openai_http_error status={getattr(e, "code", None)} body={body[:2000]}')
            err.status = getattr(e, "code", None)
            err.response_body = body
            err.llm_provider = "openai"
            err.llm_url = url
            raise err from e
        except urllib.error.URLError as e:
            err = RuntimeError(f'openai_url_error reason={getattr(e, "reason", None)}')
            err.reason = str(getattr(e, "reason", None))
            err.llm_provider = "openai"
            err.llm_url = url
            raise err from e

        txt = raw.decode('utf-8', errors='replace')
        try:
            obj = json.loads(txt)
        except Exception as e:
            err = RuntimeError('openai_bad_json_response')
            err.raw_response_text = txt
            err.llm_provider = "openai"
            err.llm_url = url
            raise err from e
        if not isinstance(obj, dict):
            err = RuntimeError('openai_bad_response')
            err.raw_response_text = txt
            err.llm_provider = "openai"
            err.llm_url = url
            raise err
        return obj

    def chat_text(
        self,
        *,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Convenience wrapper that returns the first choice's message content as text."""
        msgs: List[Dict[str, Any]] = []
        if system:
            msgs.append({'role': 'system', 'content': system})
        msgs.append({'role': 'user', 'content': prompt})
        obj = self.create_chat_completion(
            messages=msgs,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            extra=extra,
        )
        choices = obj.get('choices')
        if not isinstance(choices, list) or not choices:
            err = RuntimeError('openai_missing_choices')
            err.response_payload = obj
            err.llm_provider = "openai"
            raise err
        msg = (choices[0] or {}).get('message') or {}
        content = msg.get('content')
        if not isinstance(content, str):
            err = RuntimeError('openai_missing_content')
            err.response_payload = obj
            err.llm_provider = "openai"
            raise err
        return content


class AnthropicClient:
    """A lightweight Anthropic-compatible messages client (urllib-based)."""
    def __init__(self, base_url: str, api_key: str, default_model: Optional[str] = None, timeout_s: float = 60.0, default_max_tokens: int = 1024):
        self.base_url = (base_url or '').rstrip('/')
        self.api_key = api_key or ''
        self.default_model = default_model
        self.timeout_s = float(timeout_s)
        self.default_max_tokens = int(default_max_tokens)

    def create_message(
        self,
        *,
        messages: List[Dict[str, Any]],
        system: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Call `/v1/messages` and return the decoded JSON object."""
        use_model = model or self.default_model
        if not use_model:
            raise ValueError('missing model')
        if not self.api_key:
            raise ValueError('missing api_key')
        if not self.base_url:
            raise ValueError('missing base_url')

        use_max_tokens = int(max_tokens) if max_tokens is not None else int(self.default_max_tokens)
        if use_max_tokens < 1:
            use_max_tokens = 1

        payload: Dict[str, Any] = {
            'model': use_model,
            'messages': messages,
            'max_tokens': use_max_tokens,
        }
        if system:
            payload['system'] = system
        if temperature is not None:
            payload['temperature'] = float(temperature)
        if isinstance(extra, dict) and extra:
            payload.update(extra)

        url = self.base_url + '/v1/messages'
        req = urllib.request.Request(
            url=url,
            data=json.dumps(payload, ensure_ascii=False).encode('utf-8'),
            headers={
                'x-api-key': self.api_key,
                'anthropic-version': '2023-06-01',
                'Content-Type': 'application/json; charset=utf-8',
            },
            method='POST',
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                body = ''
            err = RuntimeError(f'anthropic_http_error status={getattr(e, "code", None)} body={body[:2000]}')
            err.status = getattr(e, "code", None)
            err.response_body = body
            err.llm_provider = "anthropic"
            err.llm_url = url
            raise err from e
        except urllib.error.URLError as e:
            err = RuntimeError(f'anthropic_url_error reason={getattr(e, "reason", None)}')
            err.reason = str(getattr(e, "reason", None))
            err.llm_provider = "anthropic"
            err.llm_url = url
            raise err from e

        txt = raw.decode('utf-8', errors='replace')
        try:
            obj = json.loads(txt)
        except Exception as e:
            err = RuntimeError('anthropic_bad_json_response')
            err.raw_response_text = txt
            err.llm_provider = "anthropic"
            err.llm_url = url
            raise err from e
        if not isinstance(obj, dict):
            err = RuntimeError('anthropic_bad_response')
            err.raw_response_text = txt
            err.llm_provider = "anthropic"
            err.llm_url = url
            raise err
        return obj

    def chat_text(
        self,
        *,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Convenience wrapper that returns the concatenated text segments."""
        msgs: List[Dict[str, Any]] = [{'role': 'user', 'content': prompt}]
        obj = self.create_message(
            messages=msgs,
            system=system,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            extra=extra,
        )
        content = obj.get('content')
        if not isinstance(content, list) or not content:
            err = RuntimeError('anthropic_missing_content')
            err.response_payload = obj
            err.llm_provider = "anthropic"
            raise err
        parts = []
        for it in content:
            if isinstance(it, dict) and isinstance(it.get('text'), str):
                parts.append(it.get('text') or '')
            elif isinstance(it, str):
                parts.append(it)
        out = ''.join(parts).strip()
        if not out:
            err = RuntimeError('anthropic_empty_text')
            err.response_payload = obj
            err.llm_provider = "anthropic"
            raise err
        return out


def get_default_client(config_path: Optional[str] = None) -> Union[OpenAIClient, AnthropicClient]:
    """Instantiate a default client based on loaded config and API key/base_url heuristics."""
    cfg: LLMConfig = load_llm_config(config_path)
    base_url = (cfg.base_url or '').strip()
    api_key = (cfg.api_key or '').strip()
    if ('anthropic' in base_url.lower()) or api_key.startswith('sk-ant-'):
        client = AnthropicClient(
            base_url=cfg.base_url,
            api_key=cfg.api_key,
            default_model=cfg.model,
            timeout_s=cfg.timeout_s,
            default_max_tokens=(cfg.max_tokens if cfg.max_tokens is not None else 1024),
        )
        client.max_retries = cfg.max_retries
        return client
    client = OpenAIClient(base_url=cfg.base_url, api_key=cfg.api_key, default_model=cfg.model, timeout_s=cfg.timeout_s)
    client.max_retries = cfg.max_retries
    return client
