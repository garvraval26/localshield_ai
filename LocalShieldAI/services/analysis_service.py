"""One entry point for the UI: input -> detector -> (optional) Llama explanation."""
from detector.errors import ModelMissingError
from detector.sms_detector import SmsDetector
from detector.url_detector import UrlDetector
from llm.llama_adapter import LlamaAdapter
from llm.prompt_templates import CLICK_WARNING
from llm.validator import fallback_response
from services.input_router import detect_input

DISCLAIMER = (
    "LocalShield AI gives an estimate, not a guarantee. A low-risk result does not "
    "prove a link or message is safe. When in doubt, contact the sender through an "
    "official channel."
)


class AnalysisService:
    def __init__(self, llama=None):
        self.llama = llama or LlamaAdapter()
        self._detectors = {}

    # ---- detectors are loaded on first use, so a missing model gives a clear message
    def _detector(self, kind):
        if kind not in self._detectors:
            self._detectors[kind] = SmsDetector() if kind == "sms" else UrlDetector()
        return self._detectors[kind]

    def model_status(self):
        """Status of the three parts, for the UI's status panel."""
        status = {}
        for kind in ("sms", "url"):
            try:
                self._detector(kind)
                status[kind] = {"ready": True, "message": "Model loaded."}
            except ModelMissingError as e:
                status[kind] = {"ready": False, "message": str(e)}
            except Exception as e:  # keep the UI alive
                status[kind] = {"ready": False, "message": f"{type(e).__name__}: {e}"}
        try:
            status["llama"] = self.llama.status()
        except Exception as e:
            status["llama"] = {"server_running": False, "model_installed": False,
                               "message": f"{type(e).__name__}: {e}"}
        return status

    def analyze(self, text, forced=None, use_llm=True):
        routed = detect_input(text, forced)
        if not routed["ok"]:
            return {"ok": False, "message": routed["message"]}

        kind = routed["kind"]
        try:
            detection = self._detector(kind).analyze(routed["text"])
        except ModelMissingError as e:
            return {"ok": False, "message": f"The {kind.upper()} model is missing: {e}"}
        except ValueError as e:
            return {"ok": False, "message": f"Could not read that input: {e}"}

        if (detection.get("rule") or {}).get("verdict") == "safe":
            # Exact allowlisted address: there are no warning signs to explain, and a small
            # model given nothing to explain tends to invent doubts. Use a fixed explanation.
            explanation = self._allowlist_explanation(detection)
        else:
            explanation = self._explain(detection, routed["text"], use_llm)
        return {
            "ok": True,
            "message": "OK",
            "kind": kind,
            "note": routed["note"],
            "input": routed["text"],
            "detection": detection,
            "explanation": explanation,
            "click_warning": CLICK_WARNING,
            "disclaimer": DISCLAIMER,
        }

    @staticmethod
    def _allowlist_explanation(detection):
        host = detection.get("host") or "This address"
        return {
            "source": "known_site_list", "model": None, "error": None,
            "explanation": (f"{host} is on the built-in list of well-known official sites, and "
                            "this is its exact address. This only confirms the web address. It "
                            "does not check the page itself or the message that sent you here."),
            "advice": ["If a message sent you here, open the site by typing its address "
                       "yourself instead.",
                       "Never share OTPs, passwords or card details because a message asked "
                       "you to.",
                       "Check that the address bar shows exactly this domain before you sign in."],
        }

    def _explain(self, detection, original, use_llm):
        site = detection.get("known_site")
        if site:  # instant answer: no model, no Llama
            return {
                "source": "known_site_list", "model": None, "error": None,
                "explanation": (f"{site} is on the built-in list of well-known official sites, "
                                "and this is its exact address. This only confirms the web "
                                "address. It does not check the page itself or the message "
                                "that sent you here."),
                "advice": ["If a message sent you here, open the site by typing its address "
                           "yourself instead.",
                           "Never share OTPs, passwords or card details because a message "
                           "asked you to.",
                           "Check that the address bar shows exactly this domain before "
                           "you sign in."],
            }
        if use_llm:
            return self.llama.explain(detection, original)  # never raises
        fb = fallback_response(detection)
        return {"source": "fallback_template", "model": None,
                "error": "Llama explanation switched off.", **fb}