import unittest
from unittest.mock import patch

from adapter import (
    Config,
    build_upstream_body,
    flatten_messages,
    make_terminal_chunk,
    normalize_bearer_token,
    normalize_non_stream,
    normalize_stream_payload,
    stream_has_finish,
)


class AdapterTest(unittest.TestCase):
    def config(self):
        return Config("127.0.0.1", 18081, "https://example.test", "key", "local", "chemellm_agent", 10, True, True, 1024)

    def test_flattens_full_openai_history(self):
        text = flatten_messages([
            {"role": "system", "content": "Be precise"},
            {"role": "user", "content": "Question one"},
            {"role": "assistant", "content": "Answer one"},
            {"role": "user", "content": [{"type": "text", "text": "Question two"}]},
        ])
        self.assertIn("[system]\nBe precise", text)
        self.assertTrue(text.endswith("[user]\nQuestion two"))

    def test_normalizes_bearer_token_from_env(self):
        self.assertEqual("abc", normalize_bearer_token("abc"))
        self.assertEqual("abc", normalize_bearer_token(" Bearer abc "))

    def test_agent_token_takes_precedence_over_legacy_api_key(self):
        with patch.dict("os.environ", {
            "CHEMELLM_AGENT_TOKEN": "agent-token",
            "CHEMELLM_API_KEY": "regular-api-key",
        }, clear=True):
            self.assertEqual("agent-token", Config.from_env().upstream_api_key)

    def test_builds_exactly_one_user_message(self):
        result = build_upstream_body({"messages": [{"role": "user", "content": "hello"}], "stream": True}, self.config())
        self.assertEqual(1, len(result["messages"]))
        self.assertEqual("user", result["messages"][0]["role"])
        self.assertTrue(result["stream"])
        self.assertTrue(result["include_tool_events"])

    def test_preserves_explicit_conversation_id(self):
        result = build_upstream_body({"messages": [{"role": "user", "content": "hello"}], "conversation_id": "cid-1"}, self.config())
        self.assertEqual("cid-1", result["conversation_id"])

    def test_normalizes_model_and_missing_fields(self):
        result = normalize_non_stream({"choices": [{"message": {"content": "ok"}}]}, "chemellm_agent")
        self.assertEqual("chat.completion", result["object"])
        self.assertEqual("chemellm_agent", result["model"])
        self.assertEqual("assistant", result["choices"][0]["message"]["role"])
        self.assertEqual("stop", result["choices"][0]["finish_reason"])
        self.assertIn("usage", result)

    def test_stream_filters_agent_events_and_keeps_content(self):
        event, role_added = normalize_stream_payload({
            "model": "chemindustry3.0pro",
            "choices": [{"index": 0, "delta": {
                "content": "answer",
                "x_status_event": {"type": "analyzing"},
                "x_tool_events": [{"tool_name": "web_search"}],
            }, "finish_reason": None}],
        }, "chemellm_agent", True)
        self.assertTrue(role_added)
        self.assertEqual("chemellm_agent", event["model"])
        self.assertEqual({"role": "assistant", "content": "answer"}, event["choices"][0]["delta"])

    def test_stream_preserves_usage_only_frame(self):
        event, role_added = normalize_stream_payload({
            "choices": [],
            "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
        }, "chemellm_agent", True)
        self.assertFalse(role_added)
        self.assertEqual([], event["choices"])
        self.assertEqual(3, event["usage"]["total_tokens"])

    def test_stream_finish_detection_and_synthetic_terminal(self):
        self.assertFalse(stream_has_finish({"choices": [{"finish_reason": None}]}))
        self.assertTrue(stream_has_finish({"choices": [{"finish_reason": "stop"}]}))
        terminal = make_terminal_chunk("chatcmpl-1", 123, "chemellm_agent")
        self.assertEqual("stop", terminal["choices"][0]["finish_reason"])
        self.assertEqual({}, terminal["choices"][0]["delta"])


if __name__ == "__main__":
    unittest.main()
