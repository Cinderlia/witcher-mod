import argparse

from .core.config import XSSConfig
from .pipeline.pipeline import ReflectionXSSPipeline
from .storage.storage import FindingStorage
from .execution.cgi_executor import CGIBinaryExecutor


def parse_args(argv):
    p = argparse.ArgumentParser()
    p.add_argument("--seed-dir", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--max-seeds", type=int, default=0)
    p.add_argument("--cgi-binary", required=True)
    p.add_argument("--cgi-arg", action="append", default=[])
    p.add_argument("--script-filename", required=True)
    p.add_argument("--document-root", default=None)
    p.add_argument("--method", default="AUTO")
    p.add_argument("--path-info", default="")
    p.add_argument("--content-type", default="application/x-www-form-urlencoded")
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--env", action="append", default=[])
    return p.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    extra_env = {}
    for item in args.env:
        if "=" in item:
            k, v = item.split("=", 1)
            extra_env[k] = v
    config = XSSConfig(
        seed_dir=args.seed_dir,
        output_dir=args.output_dir,
        max_seeds=args.max_seeds,
        cgi_binary=args.cgi_binary,
        cgi_args=args.cgi_arg,
        script_filename=args.script_filename,
        document_root=args.document_root,
        method=args.method,
        path_info=args.path_info,
        content_type=args.content_type,
        timeout_seconds=args.timeout,
        extra_env=extra_env,
    )
    executor = CGIBinaryExecutor(
        binary_path=args.cgi_binary,
        binary_args=args.cgi_arg,
        script_filename=args.script_filename,
        document_root=args.document_root,
        method=args.method,
        path_info=args.path_info,
        content_type=args.content_type,
        timeout_seconds=args.timeout,
        extra_env=extra_env,
    )
    storage = FindingStorage(config.output_dir)
    pipeline = ReflectionXSSPipeline(config=config, executor=executor, storage=storage)
    pipeline.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(None))
