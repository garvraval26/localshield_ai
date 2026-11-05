"""Local Llama adapter.

DEVELOPMENT RUNTIME ONLY: this talks to Ollama on this laptop (loopback address). The required
ARM deployment runtime is ExecuTorch (Phase 6); ExecuTorchBackend below is an explicit
placeholder so the target runtime is never silently replaced by something else.
No cloud API is ever called: non-loopback addresses are refused."""
import json
import re
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from llm.prompt_templates import build_messages
from llm.validator import LlamaResponseError, fallback_response, validate_response

DEFAULT_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "llama3.2:1b"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}

# --- SMS-only backup check (never used for URLs) ---
SCAM_WORDS = r"(scams?|phishing|fraud\w*|malicious|suspicious|dangerous|hack\w*|threat\w*)"
_SCAMMY = re.compile(r"\b" + SCAM_WORDS + r"\b", re.I)
# "not a scam", "no sign of phishing", "isn't suspicious" are fine
_NEGATED = re.compile(r"\b(not|no|isn't|isnt|n't|nothing|without)\b[^.,;:]{0,30}?\b"
                      + SCAM_WORDS + r"\b", re.I)


def _all_text(raw: str) -> str:
    """All text values of Llama's JSON reply (so field names are not scanned)."""
    try:
        obj, parts = json.loads(raw), []

        def walk(x):
            if isinstance(x, str):
                parts.append(x)
            elif isinstance(x, dict):
                for v in x.values():
                    walk(v)
            elif isinstance(x, list):
                for v in x:
                    walk(v)
        walk(obj)
        return " ".join(parts)
    except ValueError:
        return raw or ""


def _sounds_scammy(text: str) -> bool:
    return bool(_SCAMMY.search(_NEGATED.sub("", text)))


class ExecuTorchBackend:
    """Placeholder for the ARM target runtime (documented in Phase 6)."""
    runtime = "ExecuTorch (target, not implemented yet)"

    def status(self) -> dict:
        return {"runtime": self.runtime, "server_running": False, "model_installed": False,
                "model": None, "message": "ExecuTorch backend is not implemented yet (Phase 6)."}

    def generate(self, messages: list) -> str:
        raise NotImplementedError("ExecuTorch backend is planned for Phase 6.")


class OllamaBackend:
    runtime = "Ollama (development-only, local)"

    def __init__(self, base_url: str = DEFAULT_URL, model: str = DEFAULT_MODEL, timeout: int = 120):
        if urlsplit(base_url).hostname not in LOOPBACK:
            raise ValueError("Only local (loopback) addresses are allowed; remote inference is not permitted.")
        self.base_url, self.model, self.timeout = base_url.rstrip("/"), model, timeout
        # No proxies: requests to localhost must never be routed elsewhere.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _call(self, path: str, payload: dict = None, timeout: int = 5) -> dict:
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.base_url + path, data=data,
                                     headers={"Content-Type": "application/json"})
        with self._opener.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def status(self) -> dict:
        out = {"runtime": self.runtime, "model": self.model, "server_running": False, "model_installed": False}
        try:
            names = [m.get("name", "") for m in self._call("/api/tags", timeout=3).get("models", [])]
        except (urllib.error.URLError, OSError, ValueError):
            out["message"] = ("Ollama is not running. Start the Ollama app, then run: "
                              f"ollama pull {self.model}")
            return out
        out["server_running"] = True
        base = self.model.split(":")[0]
        out["model_installed"] = any(n == self.model or (":" not in self.model and n.split(":")[0] == base) for n in names)
        out["message"] = "Ready." if out["model_installed"] else f"Model not installed. Run: ollama pull {self.model}"
        return out

    def generate(self, messages: list) -> str:
        reply = self._call("/api/chat", {"model": self.model, "messages": messages, "stream": False,
                                         "format": "json",
                                         "options": {"temperature": 0.2, "num_predict": 400}},
                           timeout=self.timeout)
        return reply["message"]["content"]


class LlamaAdapter:
    """explain() never raises: it returns Llama's validated answer or a clearly labelled fallback."""

    def __init__(self, backend=None):
        self.backend = backend or OllamaBackend()

    def status(self) -> dict:
        return self.backend.status()

    def explain(self, result: dict, original_input: str) -> dict:
        st = self.backend.status()
        if not (st.get("server_running") and st.get("model_installed")):
            return self._fallback(result, st.get("message", "Llama is not available."))
        level = result.get("risk_level")
        sms_safe = result.get("type") != "url" and level == "likely_safe"
        try:
            raw = self.backend.generate(build_messages(result, original_input))
            if sms_safe and _sounds_scammy(_all_text(raw)):
                return self._fallback(result, "Llama called an ordinary message a scam; "
                                              "used the safe template instead.")
            ok = validate_response(raw, level)
        except LlamaResponseError as exc:
            return self._fallback(result, f"Llama reply rejected ({exc}).")
        except (urllib.error.URLError, OSError, KeyError, ValueError, TimeoutError) as exc:
            return self._fallback(result, f"Llama call failed: {type(exc).__name__}.")
        return {"source": "llama", "model": st.get("model"), "error": None, **ok}

    def _fallback(self, result: dict, why: str) -> dict:
        return {"source": "fallback_template", "model": None, "error": why, **fallback_response(result)}