"""V2 P4.6：写操作默认回环 + 可选 token 认证（`PLATFORM_API_TOKEN`）+ 响应标注。

设计口径（P4.5 的“默认开放”在 P4.6 收口）：

- **未设 token 时写操作只允许本机回环**：`PLATFORM_API_TOKEN` 未设置时，写操作
  （提交任务 / preflight / run / cancel）只受理回环客户端（`127.0.0.1`、`::1`、
  `localhost`、`*.localhost`）；远端客户端一律 **403**，detail 里直接给出
  “设置 `PLATFORM_API_TOKEN` 并携带 Bearer” 的处置办法。默认不再全网开放。
- **带转发头的回环也要当远端**：反向代理常与后端同机，`request.client.host`
  会是 `127.0.0.1`。因此只要请求带 `X-Forwarded-For` / `X-Real-IP` / `Forwarded`，
  就按远端处理；确实要让代理代填客户端身份时显式设 `PLATFORM_TRUST_PROXY=1`
  （只影响写操作的回环判定，别当作鉴权）。注意 uvicorn 默认 `proxy_headers=True`
  会先消费转发头、把 `request.client` 改写成真实来源，那种部署下这里看到的就是远端，
  远端照样 403——两层口径不冲突。
- **`testclient` 视为本机**：Starlette `TestClient` 的默认对端地址是
  `("testclient", 50000)`，它不经过网络、也不可能是生产流量，因此与回环等价；
  需要模拟远端请求的测试显式传 `client=("203.0.113.9", 40000)`。
- **配置即强制**：设置了 token 后，写操作必须带 `Authorization: Bearer <token>`；
  缺失 401（带 `WWW-Authenticate`），不匹配 403，与客户端地址无关
  （token 才是凭据，回环不再是通行证）。
- **GET 一律开放**：读端点不改状态，加锁只会挡住本地排查；响应体里的 `auth`
  说明当前写操作口径，HTTP 头回 `X-Platform-Auth: open|bearer`。
- **每次请求重新读取**：`PLATFORM_API_TOKEN` / `PLATFORM_TRUST_PROXY` 都用
  `os.environ` 现读，测试用 `monkeypatch.setenv` 即可切换，无模块级缓存。
- **比较用 `hmac.compare_digest`**：避免逐字节短路比较泄露 token 前缀。

不写日志、不落盘、不把 token 回显进任何响应体。
"""
from __future__ import annotations

import hmac
import ipaddress
import os

from fastapi import HTTPException, Request

TOKEN_ENV = "PLATFORM_API_TOKEN"
TRUST_PROXY_ENV = "PLATFORM_TRUST_PROXY"
AUTH_HEADER = "Authorization"
SCHEME = "Bearer"
MODE_HEADER = "X-Platform-Auth"
SCOPE_HEADER = "X-Platform-Write-Scope"

#: 不经过网络的本地对端：回环地址之外只需认 `localhost` 与 TestClient 的默认 peer。
LOOPBACK_HOSTS = frozenset({"localhost", "testclient"})
FORWARD_HEADERS = ("x-forwarded-for", "x-real-ip", "forwarded")


def configured_token() -> str:
    """当前生效的 token；每次调用重新读环境变量。"""
    return (os.environ.get(TOKEN_ENV) or "").strip()


def enabled() -> bool:
    return bool(configured_token())


def trust_proxy() -> bool:
    """是否把转发头当作可信客户端来源（默认不信：同机反代不等于本机调用）。"""
    return (os.environ.get(TRUST_PROXY_ENV) or "").strip().lower() in {
        "1", "true", "yes", "on"}


def auth_info() -> dict:
    """可直接放进响应体的鉴权说明（不含 token 本身）。"""
    if enabled():
        return {
            "mode": "bearer",
            "token_required": True,
            "write_scope": "token",
            "loopback_only": False,
            "remote_writes": "token",
            "env": TOKEN_ENV,
            "header": f"{AUTH_HEADER}: {SCHEME} <token>",
            "note": (f"{TOKEN_ENV} 已设置：写操作必须携带 Bearer token，"
                     "远端与本机一致；GET 保持开放。"),
        }
    return {
        "mode": "open",
        "token_required": False,
        "write_scope": "loopback",
        "loopback_only": True,
        "remote_writes": "denied",
        "env": TOKEN_ENV,
        "header": f"{AUTH_HEADER}: {SCHEME} <token>",
        "note": (f"{TOKEN_ENV} 未设置：写操作仅限本机回环（127.0.0.1 / ::1 / localhost），"
                 "远端写请求返回 403；对外暴露前请设置 token 并携带 Bearer 头。"),
    }


def _client_host(request: Request) -> str:
    client = getattr(request, "client", None)
    if client is None:
        return ""
    host = getattr(client, "host", None)
    if host is None:
        try:
            host = client[0]        # 老版本 Starlette 用 (host, port) 元组
        except (TypeError, IndexError, KeyError):
            host = ""
    return str(host or "").strip()


def is_loopback_host(host: str) -> bool:
    """主机名/地址是否属于本机回环（含 IPv6、`[::1]` 写法与 `*.localhost`）。"""
    value = (host or "").strip().strip("[]").lower()
    if not value:
        return False
    if value in LOOPBACK_HOSTS:
        return True
    if value.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def has_forward_headers(request: Request) -> bool:
    return any((request.headers.get(name) or "").strip()
               for name in FORWARD_HEADERS)


def client_is_loopback(request: Request) -> bool:
    """写操作能否按“本机”受理：回环对端 + 没有不可信的转发头。"""
    if not is_loopback_host(_client_host(request)):
        return False
    return trust_proxy() or not has_forward_headers(request)


def _presented(request: Request) -> str:
    raw = (request.headers.get(AUTH_HEADER) or "").strip()
    if not raw:
        return ""
    parts = raw.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != SCHEME.lower():
        return ""
    return parts[1].strip()


def check_write(request: Request) -> dict:
    """写操作守卫：有 token → 校验 Bearer；无 token → 只放行本机回环。"""
    expected = configured_token()
    if expected:
        presented = _presented(request)
        if not presented:
            raise HTTPException(
                401, f"write requires Bearer token（{TOKEN_ENV} 已设置）",
                headers={"WWW-Authenticate": f'{SCHEME} realm="vulnmap-platform"'})
        if not hmac.compare_digest(presented, expected):
            raise HTTPException(403, "invalid token")
        return auth_info()

    if not client_is_loopback(request):
        host = _client_host(request) or "unknown"
        raise HTTPException(
            403,
            (f"write denied: client {host} is not loopback；{TOKEN_ENV} 未设置时写操作"
             f"只允许 127.0.0.1 / ::1。需要远端写入请设置 {TOKEN_ENV} 并发送 "
             f"{AUTH_HEADER}: {SCHEME} <token>。"),
            headers={MODE_HEADER: "denied"})
    info = auth_info()
    info["request_scope"] = "loopback"
    return info


def write_guard(request: Request) -> dict:
    """FastAPI 依赖：`auth: dict = Depends(write_guard)`。"""
    return check_write(request)
