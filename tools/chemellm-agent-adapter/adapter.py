#!/usr/bin/env python3
"""OpenAI Chat Completions facade for the ChemELLM managed Agent API."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import ssl
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, BinaryIO


LOG = logging.getLogger("chemellm-agent-adapter")


@dataclass(frozen=True)
class Config:
    listen_host: str
    listen_port: int
    upstream_url: str
    upstream_api_key: str
    inbound_api_key: str
    public_model: str
    timeout_seconds: float
    include_tool_events: bool
    verify_tls: bool
    max_body_bytes: int

    @classmethod
    def from_env(cls) -> "Config":
        listen = os.getenv("LISTEN", "127.0.0.1:18081")
        host, port = listen.rsplit(":", 1)
        return cls(
            listen_host=host,
            listen_port=int(port),
            upstream_url=os.getenv(
                "CHEMELLM_UPSTREAM_URL",
                "https://chemellm.dicp.ac.cn/v1.0/agent/chat/completions",
            ),
            upstream_api_key=normalize_bearer_token(
                os.getenv("CHEMELLM_AGENT_TOKEN", "") or os.getenv("CHEMELLM_API_KEY", "")
            ),
            inbound_api_key=os.getenv("ADAPTER_API_KEY", ""),
            public_model=os.getenv("PUBLIC_MODEL", "chemellm_agent"),
            timeout_seconds=float(os.getenv("UPSTREAM_TIMEOUT_SECONDS", "600")),
            include_tool_events=parse_bool(os.getenv("INCLUDE_TOOL_EVENTS", "true")),
            verify_tls=parse_bool(os.getenv("VERIFY_TLS", "true")),
            max_body_bytes=int(os.getenv("MAX_BODY_BYTES", str(8 * 1024 * 1024))),
        )


def parse_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def normalize_bearer_token(value: str) -> str:
    token = value.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def openai_error(message: str, error_type: str = "api_error", code: Any = None) -> dict[str, Any]:
    return {"error": {"message": message, "type": error_type, "param": None, "code": code}}


def content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return "" if content is None else json.dumps(content, ensure_ascii=False)
    parts: list[str] = []
    for part in content:
        if not isinstance(part, dict):
            continue
        if part.get("type") in {"text", "input_text", "output_text"} and isinstance(part.get("text"), str):
            parts.append(part["text"])
        elif part.get("type") in {"image_url", "input_image"}:
            parts.append("[图片内容未转发：ChemELLM Agent 接口仅接受文本]")
    return "\n".join(parts)


def flatten_messages(messages: Any) -> str:
    """Collapse OpenAI history into the Agent API's exactly-one-user-message shape."""
    if not isinstance(messages, list) or not messages:
        raise ValueError("messages must be a non-empty array")

    sections: list[str] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role", "user"))
        text = content_to_text(message.get("content"))
        tool_calls = message.get("tool_calls")
        if isinstance(tool_calls, list) and tool_calls:
            rendered = json.dumps(tool_calls, ensure_ascii=False, separators=(",", ":"))
            text = (text + "\n" if text else "") + "历史工具调用：" + rendered
        if role == "tool":
            call_id = message.get("tool_call_id", "")
            text = f"工具结果（call_id={call_id}）：{text}"
        if text.strip():
            sections.append(f"[{role}]\n{text.strip()}")

    if not sections:
        raise ValueError("messages contain no textual content")
    return "以下是完整对话上下文。请回答最后一条用户请求。\n\n" + "\n\n".join(sections)


def build_upstream_body(body: dict[str, Any], config: Config) -> dict[str, Any]:
    upstream: dict[str, Any] = {
        "messages": [{"role": "user", "content": flatten_messages(body.get("messages"))}],
        "stream": bool(body.get("stream", False)),
        "include_tool_events": config.include_tool_events,
    }
    conversation_id = body.get("conversation_id")
    if isinstance(conversation_id, str) and conversation_id:
        upstream["conversation_id"] = conversation_id
    return upstream


def normalize_non_stream(payload: dict[str, Any], public_model: str) -> dict[str, Any]:
    result = dict(payload)
    result.setdefault("id", "chatcmpl-" + uuid.uuid4().hex)
    result["object"] = "chat.completion"
    result.setdefault("created", int(time.time()))
    result["model"] = public_model
    choices = result.get("choices")
    if not isinstance(choices, list) or not choices:
        result["choices"] = [{
            "index": 0,
            "message": {"role": "assistant", "content": ""},
            "finish_reason": "stop",
        }]
    else:
        normalized = []
        for index, choice in enumerate(choices):
            if not isinstance(choice, dict):
                continue
            item = dict(choice)
            item.setdefault("index", index)
            message = item.get("message")
            if not isinstance(message, dict):
                message = {"role": "assistant", "content": ""}
            else:
                message = dict(message)
                message.setdefault("role", "assistant")
                message.setdefault("content", "")
            item["message"] = message
            item.setdefault("finish_reason", "stop")
            normalized.append(item)
        result["choices"] = normalized
    result.setdefault("usage", {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})
    return result


def normalize_stream_payload(payload: dict[str, Any], public_model: str, include_role: bool) -> tuple[dict[str, Any], bool]:
    result = dict(payload)
    result["model"] = public_model
    role_added = False
    choices = result.get("choices")
    if not isinstance(choices, list):
        return result, role_added
    filtered = []
    for choice in choices:
        if not isinstance(choice, dict):
            continue
        item = dict(choice)
        delta = item.get("delta")
        if isinstance(delta, dict):
            clean_delta: dict[str, Any] = {}
            if include_role:
                clean_delta["role"] = "assistant"
                include_role = False
                role_added = True
            if isinstance(delta.get("content"), str):
                clean_delta["content"] = delta["content"]
            item["delta"] = clean_delta
        filtered.append(item)
    result["choices"] = filtered
    return result, role_added


def stream_has_finish(payload: dict[str, Any]) -> bool:
    choices = payload.get("choices")
    return isinstance(choices, list) and any(
        isinstance(choice, dict) and choice.get("finish_reason") is not None
        for choice in choices
    )


def make_terminal_chunk(completion_id: str, created: int, public_model: str) -> dict[str, Any]:
    return {
        "id": completion_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": public_model,
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "chemellm-agent-adapter/1.0"

    @property
    def config(self) -> Config:
        return self.server.config  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        LOG.info("%s - %s", self.address_string(), fmt % args)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/")
        if path in {"", "/healthz"}:
            self.send_json(200, {"status": "ok", "model": self.config.public_model})
            return
        if path in {"/models", "/v1/models"}:
            if not self.authorized():
                return
            self.send_json(200, {
                "object": "list",
                "data": [{"id": self.config.public_model, "object": "model", "owned_by": "chemellm"}],
            })
            return
        self.send_json(404, openai_error("Not found", "invalid_request_error"))

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/")
        if path not in {"/chat/completions", "/v1/chat/completions"}:
            self.send_json(404, openai_error("Not found", "invalid_request_error"))
            return
        if not self.authorized():
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > self.config.max_body_bytes:
                raise ValueError("invalid request body size")
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("request body must be a JSON object")
            requested_model = body.get("model")
            if requested_model not in {None, "", self.config.public_model}:
                self.send_json(404, openai_error(f"Model '{requested_model}' is not served by this adapter", "invalid_request_error", "model_not_found"))
                return
            upstream_body = build_upstream_body(body, self.config)
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json(400, openai_error(str(exc), "invalid_request_error"))
            return

        try:
            response = self.call_upstream(upstream_body)
            if upstream_body["stream"]:
                self.proxy_stream(response)
            else:
                with response:
                    payload = json.load(response)
                self.send_json(200, normalize_non_stream(payload, self.config.public_model))
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                payload = openai_error(raw.decode("utf-8", "replace") or exc.reason)
            self.send_json(exc.code, payload)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            LOG.exception("upstream request failed")
            self.send_json(502, openai_error(f"ChemELLM upstream request failed: {exc}"))

    def authorized(self) -> bool:
        expected = self.config.inbound_api_key
        if not expected:
            return True
        supplied = self.headers.get("Authorization", "")
        if supplied == "Bearer " + expected:
            return True
        self.send_json(401, openai_error("Invalid adapter API key", "authentication_error"))
        return False

    def call_upstream(self, body: dict[str, Any]) -> BinaryIO:
        request = urllib.request.Request(
            self.config.upstream_url,
            data=json_bytes(body),
            headers={
                "Authorization": "Bearer " + self.config.upstream_api_key,
                "Content-Type": "application/json",
                "Accept": "text/event-stream" if body["stream"] else "application/json",
                "User-Agent": self.server_version,
            },
            method="POST",
        )
        context = None if self.config.verify_tls else ssl._create_unverified_context()
        return urllib.request.urlopen(request, timeout=self.config.timeout_seconds, context=context)

    def proxy_stream(self, upstream: BinaryIO) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "close")
        self.end_headers()
        sent_role = False
        sent_done = False
        sent_finish = False
        completion_id = "chatcmpl-" + uuid.uuid4().hex
        created = int(time.time())
        try:
            with upstream:
                for raw in upstream:
                    line = raw.decode("utf-8", "replace").strip()
                    if not line:
                        continue
                    data = line[5:].strip() if line.startswith("data:") else line
                    if data == "[DONE]":
                        self.write_sse("[DONE]")
                        sent_done = True
                        break
                    try:
                        payload = json.loads(data)
                    except json.JSONDecodeError:
                        LOG.warning("ignored malformed upstream SSE line: %r", line[:500])
                        continue
                    if not isinstance(payload, dict):
                        LOG.warning("ignored non-object upstream SSE payload")
                        continue
                    if isinstance(payload.get("id"), str) and payload["id"]:
                        completion_id = payload["id"]
                    if isinstance(payload.get("created"), int):
                        created = payload["created"]
                    payload, role_added = normalize_stream_payload(payload, self.config.public_model, not sent_role)
                    sent_role = sent_role or role_added
                    sent_finish = sent_finish or stream_has_finish(payload)
                    self.write_sse(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        except (BrokenPipeError, ConnectionResetError):
            LOG.info("downstream client disconnected")
            return
        except Exception:
            # Once HTTP 200 and some SSE frames have been sent, a JSON error
            # response is impossible. Close the OpenAI stream cleanly and keep
            # the real upstream failure in server logs for diagnosis.
            LOG.exception("ChemELLM stream interrupted; emitting a synthetic terminal frame")

        try:
            if not sent_finish:
                terminal = make_terminal_chunk(completion_id, created, self.config.public_model)
                self.write_sse(json.dumps(terminal, ensure_ascii=False, separators=(",", ":")))
            if not sent_done:
                self.write_sse("[DONE]")
        except (BrokenPipeError, ConnectionResetError):
            LOG.info("downstream client disconnected during stream finalization")

    def write_sse(self, data: str) -> None:
        self.wfile.write(("data: " + data + "\n\n").encode("utf-8"))
        self.wfile.flush()

    def send_json(self, status: int, payload: Any) -> None:
        data = json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, config: Config):
        self.config = config
        super().__init__((config.listen_host, config.listen_port), Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    config = Config.from_env()
    if not config.upstream_api_key:
        raise SystemExit("CHEMELLM_AGENT_TOKEN is required (CHEMELLM_API_KEY remains supported for compatibility)")
    if args.check_config:
        print(f"ok: listen={config.listen_host}:{config.listen_port} model={config.public_model} upstream={config.upstream_url}")
        return
    server = Server(config)
    def stop_server(*_: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop_server)
    LOG.info("listening on %s:%d for model %s", config.listen_host, config.listen_port, config.public_model)
    server.serve_forever()


if __name__ == "__main__":
    main()
