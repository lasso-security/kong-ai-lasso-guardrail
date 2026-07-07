"""Mock server for the Kong e2e: serves BOTH the Lasso classify API and a fake LLM upstream.

Endpoints:
  POST /gateway/v3/classify        -> {deputies, findings, violations_detected}
  POST /gateway/v3/classifix       -> above + masked messages[] + span offsets
  POST /v1/chat/completions        -> echoes the received prompt into the completion
                                      (so request-masking is visible downstream)
  POST /v1/pii/chat/completions    -> returns a FIXED completion containing PII
                                      (so response-masking is visible to the client)

Trigger substrings (matched on concatenated message text): LASSO_BLOCK, LASSO_MASK.
"""
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def text_of(body):
    parts = []
    for m in body.get("messages") or []:
        c = m.get("content")
        if isinstance(c, str):
            parts.append(c)
        elif isinstance(c, list):
            parts += [b.get("text", "") for b in c if isinstance(b, dict)]
    return " ".join(parts)


def classify(text, masking):
    if "LASSO_BLOCK" in text:
        return {"deputies": {"jailbreak": True},
                "findings": {"jailbreak": [{"message_index": 0, "name": "pi",
                             "action": "BLOCK", "severity": "HIGH"}]},
                "violations_detected": True}
    if "LASSO_MASK" in text:
        body = {"deputies": {"pattern-detection": True},
                "findings": {"pattern-detection": [{"message_index": 0, "name": "email",
                             "action": "AUTO_MASKING", "severity": "LOW"}]},
                "violations_detected": True}
        if masking:
            m = EMAIL.search(text)
            if m:
                body["findings"]["pattern-detection"][0].update(
                    {"start": m.start(), "end": m.end(), "mask": "<EMAIL>"})
                body["messages"] = [{"role": "user",
                                     "content": text[:m.start()] + "<EMAIL>" + text[m.end():]}]
        return body
    return {"deputies": {}, "findings": {}, "violations_detected": False}


def completion(content):
    return {"id": "chatcmpl-mock", "object": "chat.completion",
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": content}}]}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            body = {}
        p = self.path
        if p in ("/gateway/v3/classify", "/gateway/v3/classifix"):
            # Surface what the plugin sent so the e2e can assert on sessionId/source.
            print("LASSO_CALL sessionId=%s source=%s type=%s"
                  % (body.get("sessionId"), (body.get("source") or {}).get("type"),
                     body.get("messageType")), flush=True)
        if p == "/gateway/v3/classify":
            return self._send(200, classify(text_of(body), masking=False))
        if p == "/gateway/v3/classifix":
            return self._send(200, classify(text_of(body), masking=True))
        if p == "/v1/chat/completions":
            # echo what the upstream actually received (post-guardrail) into the reply
            return self._send(200, completion("upstream received: " + text_of(body)))
        if p == "/v1/pii/chat/completions":
            return self._send(200, completion("Sure — contact me at agent@example.com LASSO_MASK"))
        return self._send(404, {"error": "not found"})


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
