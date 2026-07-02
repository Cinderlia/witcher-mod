"""Quick manual smoke test for the configured LLM client."""

import argparse
import os
import sys
import time

# Add project root to sys.path so `import llm_utils` works when running directly
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    # Allow running this file directly while still importing the local package.
    sys.path.insert(0, _ROOT)

from llm_utils import get_default_client


def _shorten(s: str, limit: int = 2000) -> str:
    if not isinstance(s, str):
        return ""
    t = s.strip()
    if len(t) <= limit:
        return t
    return t[:limit] + "\n...[truncated]..."


def main():
    ap = argparse.ArgumentParser(description="LLM client smoke test")
    ap.add_argument("--prompt", default="给我一个一句话总结")
    ap.add_argument("--system", default="你是一个严谨的代码助手")
    ap.add_argument("--temperature", type=float, default=None)
    ap.add_argument("--model", type=str, default=None)
    ap.add_argument("--max-tokens", type=int, default=None)
    args = ap.parse_args()

    client = get_default_client()
    meta = {
        "client_type": type(client).__name__,
        "base_url": getattr(client, "base_url", None),
        "model": getattr(client, "default_model", None),
        "timeout_s": getattr(client, "timeout_s", None),
    }
    print("Client:", meta)
    print("Sending chat_text...")
    t0 = time.perf_counter()
    try:
        txt = client.chat_text(
            prompt=args.prompt,
            system=args.system,
            model=args.model,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
        )
        dt_ms = int((time.perf_counter() - t0) * 1000)
        print(f"OK in {dt_ms} ms")
        print(_shorten(txt, limit=4000))
    except Exception as e:
        dt_ms = int((time.perf_counter() - t0) * 1000)
        print(f"FAILED in {dt_ms} ms: {e}")
        raise


if __name__ == "__main__":
    main()
