"""Async helpers for calling an LLM with retries and structured error reporting."""

import asyncio
import json
import os
import re
import time
import traceback
try:
    from dataclasses import dataclass
except Exception:
    from compat_dataclasses import dataclass
from typing import Optional


_STATUS_RE = re.compile(r'\bstatus=(\d{3})\b', flags=re.IGNORECASE)


@dataclass(frozen=True)
class LLMCallFailure(Exception):
    """Raised when an LLM call fails permanently (optionally after retries)."""
    message: str
    retryable: bool = False
    status: Optional[int] = None
    details: Optional[dict] = None

    def __str__(self) -> str:
        return self.message


def _extract_status(e: BaseException) -> Optional[int]:
    """Parse `status=NNN` from exception text if present."""
    msg = str(e) if e is not None else ''
    m = _STATUS_RE.search(msg)
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def _is_retryable_status(status: Optional[int]) -> bool:
    """Return True if an HTTP status is typically transient."""
    if status is None:
        return False
    if status in (408, 409, 425, 429):
        return True
    if 500 <= int(status) <= 599:
        return True
    return False


def _is_retryable_exception(e: BaseException) -> bool:
    """Heuristic detection for transient network/API failures."""
    msg = str(e) if e is not None else ''
    if isinstance(e, (asyncio.TimeoutError, TimeoutError)):
        return True
    if isinstance(e, OSError):
        winerror = getattr(e, 'winerror', None)
        err_no = getattr(e, 'errno', None)
        if winerror in (10053, 10054, 10060, 10061, 121, 1231):
            return True
        if err_no in (10053, 10054, 10060, 10061):
            return True
    if 'openai_url_error' in msg:
        return True
    if 'timed out' in msg.lower():
        return True
    if 'timeout' in msg.lower():
        return True
    if 'temporarily unavailable' in msg.lower():
        return True
    if 'connection reset' in msg.lower():
        return True
    if 'connection aborted' in msg.lower():
        return True
    if 'connection refused' in msg.lower():
        return True
    if 'ssl' in msg.lower():
        return True
    if 'remote end closed connection' in msg.lower():
        return True
    if _is_retryable_status(_extract_status(e)):
        return True
    return False


try:
    _asyncio_to_thread = asyncio.to_thread
except Exception:
    _asyncio_to_thread = None


async def _to_thread(func, *args, **kwargs):
    if _asyncio_to_thread is not None:
        return await _asyncio_to_thread(func, *args, **kwargs)
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: func(*args, **kwargs))


def _create_task(coro):
    ct = getattr(asyncio, "create_task", None)
    if ct is not None:
        return ct(coro)
    return asyncio.ensure_future(coro)


def _client_log_fields(client) -> dict:
    """Extract safe metadata about the client for logging."""
    if client is None:
        return {'llm_client_type': None}
    out = {'llm_client_type': type(client).__name__}
    try:
        base_url = getattr(client, 'base_url', None)
        if isinstance(base_url, str) and base_url:
            out['llm_base_url'] = base_url
    except Exception:
        pass
    try:
        timeout_s = getattr(client, 'timeout_s', None)
        if timeout_s is not None:
            out['llm_timeout_s'] = timeout_s
    except Exception:
        pass
    try:
        default_model = getattr(client, 'default_model', None)
        if isinstance(default_model, str) and default_model:
            out['llm_model'] = default_model
    except Exception:
        pass
    return out


def _exc_log_fields(e: BaseException) -> dict:
    """Extract exception details for logs while bounding size."""
    if e is None:
        return {'exc_type': None}
    out = {
        'exc_type': type(e).__name__,
        'exc_str': str(e)[:2000],
        'exc_repr': repr(e)[:2000],
    }
    try:
        winerror = getattr(e, 'winerror', None)
        if winerror is not None:
            out['exc_winerror'] = winerror
    except Exception:
        pass
    try:
        err_no = getattr(e, 'errno', None)
        if err_no is not None:
            out['exc_errno'] = err_no
    except Exception:
        pass
    try:
        cause = getattr(e, '__cause__', None)
        if cause is not None:
            out['exc_cause'] = f'{type(cause).__name__}: {str(cause)[:500]}'
    except Exception:
        pass
    try:
        ctx = getattr(e, '__context__', None)
        if ctx is not None:
            out['exc_context'] = f'{type(ctx).__name__}: {str(ctx)[:500]}'
    except Exception:
        pass
    try:
        tb = ''.join(traceback.format_exception(type(e), e, e.__traceback__))
        out['exc_tb'] = tb[-4000:]
    except Exception:
        pass
    return out


def _is_timeout_exception(e: BaseException) -> bool:
    if isinstance(e, (asyncio.TimeoutError, TimeoutError)):
        return True
    msg = str(e) if e is not None else ''
    return 'timed out' in msg.lower() or 'timeout' in msg.lower()


def _safe_json_value(value):
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple)):
        return [_safe_json_value(v) for v in value]
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            out[str(k)] = _safe_json_value(v)
        return out
    return str(value)


def _exception_details(e: BaseException) -> dict:
    details = {
        'exception_type': type(e).__name__ if e is not None else None,
        'message': str(e) if e is not None else '',
        'repr': repr(e) if e is not None else '',
        'is_timeout': _is_timeout_exception(e),
        'status': _extract_status(e),
    }
    for attr in ('llm_provider', 'llm_url', 'reason', 'response_body', 'raw_response_text', 'response_payload'):
        try:
            val = getattr(e, attr, None)
        except Exception:
            val = None
        if val is not None:
            details[attr] = _safe_json_value(val)
    try:
        tb = ''.join(traceback.format_exception(type(e), e, e.__traceback__))
        details['traceback'] = tb
    except Exception:
        pass
    return details


def write_llm_failure_artifact(
    *,
    failure_dir: str,
    failure_name: str,
    prompt_path: Optional[str],
    failure: LLMCallFailure,
    extra: Optional[dict] = None,
) -> str:
    if not isinstance(failure_dir, str) or not failure_dir.strip():
        return ''
    if not isinstance(failure_name, str) or not failure_name.strip():
        failure_name = 'llm_failure'
    try:
        os.makedirs(failure_dir, exist_ok=True)
    except Exception:
        return ''
    payload = {
        'timestamp': int(time.time()),
        'prompt_path': prompt_path or '',
        'message': str(failure),
        'retryable': bool(getattr(failure, 'retryable', False)),
        'status': getattr(failure, 'status', None),
        'details': _safe_json_value(getattr(failure, 'details', None) or {}),
    }
    if isinstance(extra, dict) and extra:
        payload['context'] = _safe_json_value(extra)
    out_path = os.path.join(failure_dir, f'{failure_name}.json')
    with open(out_path, 'w', encoding='utf-8') as wf:
        json.dump(payload, wf, ensure_ascii=False, indent=2)
    return out_path


async def chat_text_with_retries(
    *,
    client,
    prompt: str,
    system: Optional[str] = None,
    temperature: Optional[float] = None,
    logger=None,
    max_attempts: int = 3,
    base_delay_s: float = 1.0,
    backoff: float = 2.0,
    call_timeout_s: Optional[float] = None,
    call_index: Optional[int] = None,
    taint_type: Optional[str] = None,
    taint_name: Optional[str] = None,
    response_validator=None,
    response_validator_name: Optional[str] = None,
) -> str:
    """Call `client.chat_text` with retries, exponential backoff, and optional timeout."""
    if max_attempts < 1:
        max_attempts = 1
    delay = float(base_delay_s)
    last_exc = None
    for attempt in range(1, int(max_attempts) + 1):
        try:
            coro = _to_thread(client.chat_text, prompt=prompt, system=system, temperature=temperature)
            if call_timeout_s is not None:
                try:
                    resp = await asyncio.wait_for(coro, timeout=float(call_timeout_s))
                except Exception:
                    raise
            else:
                resp = await coro
            if response_validator is not None:
                ok = False
                try:
                    ok = bool(response_validator(resp))
                except Exception:
                    ok = False
                if not ok:
                    if logger is not None:
                        fields = {
                            'call_index': call_index,
                            'attempt': attempt,
                            'max_attempts': max_attempts,
                            'taint_type': taint_type,
                            'taint_name': taint_name,
                            'prompt_chars': len(prompt or ''),
                            'system_chars': len(system or '') if system else 0,
                            'call_timeout_s': call_timeout_s,
                            'validator': response_validator_name or getattr(response_validator, '__name__', None),
                            'resp_chars': len(resp or ''),
                        }
                        fields.update(_client_log_fields(client))
                        logger.warning('llm_response_invalid_json', **fields)
                    if attempt < int(max_attempts):
                        await asyncio.sleep(delay)
                        delay = max(0.0, delay * float(backoff))
                        continue
                    failure_details = {
                        'failure_kind': 'invalid_response',
                        'attempt': attempt,
                        'max_attempts': int(max_attempts),
                        'call_index': call_index,
                        'taint_type': taint_type,
                        'taint_name': taint_name,
                        'validator': response_validator_name or getattr(response_validator, '__name__', None),
                        'response_text': resp,
                        'call_timeout_s': call_timeout_s,
                    }
                    failure_details.update(_client_log_fields(client))
                    raise LLMCallFailure(
                        message='llm_response_invalid_json',
                        retryable=False,
                        status=None,
                        details=failure_details,
                    )
            return resp
        except Exception as e:
            last_exc = e
            if isinstance(e, LLMCallFailure):
                raise
            status = _extract_status(e)
            retryable = _is_retryable_exception(e)
            failure_details = {
                'failure_kind': 'exception',
                'attempt': attempt,
                'max_attempts': int(max_attempts),
                'call_index': call_index,
                'taint_type': taint_type,
                'taint_name': taint_name,
                'call_timeout_s': call_timeout_s,
            }
            failure_details.update(_client_log_fields(client))
            failure_details.update(_exception_details(e))
            if logger is not None:
                fields = {
                    'call_index': call_index,
                    'attempt': attempt,
                    'max_attempts': max_attempts,
                    'status': status,
                    'taint_type': taint_type,
                    'taint_name': taint_name,
                    'prompt_chars': len(prompt or ''),
                    'system_chars': len(system or '') if system else 0,
                    'call_timeout_s': call_timeout_s,
                }
                fields.update(_client_log_fields(client))
                fields.update(_exc_log_fields(e))
                if retryable and attempt < int(max_attempts):
                    logger.warning(
                        'llm_retry',
                        delay_s=delay,
                        **fields,
                    )
                else:
                    logger.exception(
                        'llm_call_fatal',
                        **fields,
                    )
            if retryable and attempt < int(max_attempts):
                await asyncio.sleep(delay)
                delay = max(0.0, delay * float(backoff))
                continue
            raise LLMCallFailure(
                message=f'{type(e).__name__}: {e}',
                retryable=retryable,
                status=status,
                details=failure_details,
            )
    details = None
    if last_exc is not None:
        details = _exception_details(last_exc)
    raise LLMCallFailure(
        message=str(last_exc) if last_exc is not None else 'llm_call_failed',
        details=details,
    )


async def run_calls_concurrently(call_coros, *, max_concurrency: int = 6):
    """Run awaitables concurrently with a max concurrency limit."""
    sem = asyncio.Semaphore(max(1, int(max_concurrency)))

    async def _run_one(c):
        async with sem:
            return await c

    tasks = [_create_task(_run_one(c)) for c in (call_coros or [])]
    if not tasks:
        return []
    return await asyncio.gather(*tasks)
