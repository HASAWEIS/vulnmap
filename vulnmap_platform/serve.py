#!/usr/bin/env python3
"""启动 vulnmap 平台。用法：python3 vulnmap_platform/serve.py [--port 8900]"""
import argparse, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import uvicorn

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8900)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()
    print(f"vulnmap 平台 -> http://{a.host}:{a.port}/")
    uvicorn.run("vulnmap_platform.api.app:app", host=a.host, port=a.port, log_level="warning")
