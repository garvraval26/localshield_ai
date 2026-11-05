"""LocalShield AI - Streamlit dashboard. Everything runs on this computer."""
import html

import streamlit as st

from services.analysis_service import AnalysisService
from services.history import History

st.set_page_config(page_title="LocalShield AI", layout="wide")

st.markdown(
    """
<style>
#MainMenu, footer { visibility: hidden; }
.block-container { max-width: 820px; padding-top: 2.4rem; padding-bottom: 3rem; }

.ls-brand { font-size: 1.9rem; font-weight: 700; color: #2B2F36; letter-spacing: -0.01em; }
.ls-brand span { color: #2F5D62; }

.ls-notice { background: #FBF1DF; border: 1px solid #EBD9B4; border-radius: 10px;
             padding: 0.8rem 1rem; color: #5A4513; font-size: 0.95rem; margin: 0 0 1.4rem 0; }

.ls-card { border-radius: 12px; padding: 1.2rem 1.4rem; margin: 1.3rem 0 0.6rem 0; border: 1px solid; }
.ls-eyebrow { font-size: 0.8rem; color: #5E6470; }
.ls-level { font-size: 1.8rem; font-weight: 700; line-height: 1.25; margin: 0.1rem 0 0.25rem 0; }
.ls-score { color: #2B2F36; font-size: 0.97rem; }
.ls-bar { height: 7px; background: rgba(0,0,0,0.09); border-radius: 4px; margin: 0.55rem 0; }
.ls-bar > div { height: 7px; border-radius: 4px; }
.ls-fine { color: #5E6470; font-size: 0.88rem; line-height: 1.45; }

.ls-h { font-size: 1.12rem; font-weight: 600; color: #2B2F36; margin: 1.7rem 0 0.5rem 0; }
.ls-panel { background: #FFFFFF; border: 1.5px solid #000000; border-radius: 10px;
            padding: 0.9rem 1.1rem; color: #2B2F36; line-height: 1.6; }
.ls-list { margin: 0.1rem 0 0 1.1rem; padding: 0; color: #2B2F36; }
.ls-list li { margin: 0.3rem 0; line-height: 1.5; }

.ls-row { display: flex; gap: 0.6rem; margin: 0 0 0.8rem 0; font-size: 0.92rem; }
.ls-dot { width: 9px; height: 9px; border-radius: 50%; margin-top: 0.45rem; flex: 0 0 9px; }
.ls-local { background: #FFFFFF; border: 1px solid #E3E0D8; border-radius: 10px;
            padding: 0.65rem 0.8rem; font-size: 0.88rem; color: #2B2F36; margin-bottom: 1rem; }

[data-testid="stForm"] { background: #FFFFFF; border: 1px solid #E3E0D8; border-radius: 12px; padding: 1.2rem; }
[data-testid="stFormSubmitButton"] button { background: #2F5D62; color: #FFFFFF; border: 0;
        border-radius: 8px; padding: 0.5rem 1.6rem; font-weight: 600; }
[data-testid="stFormSubmitButton"] button:hover { background: #25494D; color: #FFFFFF; }
.stTabs [data-baseweb="tab-list"] { gap: 1.6rem; }
</style>
""",
    unsafe_allow_html=True,
)

# (text colour, card background, card border)
LEVELS = {
    "likely_safe": ("Low risk", "#2F6B4B", "#EAF3EE", "#CFE3D6"),
    "suspicious": ("Suspicious", "#9A6410", "#FBF1DF", "#EBD9B4"),
    "high_risk": ("High risk", "#A33232", "#F8E7E7", "#E8C6C6"),
}


def e(value):
    return html.escape(str(value))


@st.cache_resource
def get_service():
    return AnalysisService()


@st.cache_resource
def get_history():
    return History()


service = get_service()
history = get_history()


def heading(text):
    st.markdown(f'<div class="ls-h">{e(text)}</div>', unsafe_allow_html=True)


def bullet_list(items):
    body = "".join(f"<li>{e(i)}</li>" for i in items)
    st.markdown(f'<ul class="ls-list">{body}</ul>', unsafe_allow_html=True)


def show_result(result):
    if not result["ok"]:
        st.error(result["message"])
        return

    det = result["detection"]
    exp = result["explanation"]
    level = det["risk_level"]
    label, color, bg, border = LEVELS.get(level, (level, "#2B2F36", "#FFFFFF", "#E3E0D8"))
    score = max(0.0, min(1.0, float(det["score"])))
    known = det.get("known_site")

    if known:
        label = "Known site"
        score_line = f"{known} is on the built-in list of well-known sites."
        fine = "This confirms the web address only, not the page. It is not a guarantee of safety."
    else:
        score_line = f"Risk score {score:.2f} out of 1.00"
        fine = ("A low score does not mean this is safe."
                if level == "likely_safe" else "The score is an estimate, not a probability.")
    if det.get("rule_floor_applied"):
        fine += (" Raised to at least 'suspicious' by a structural rule "
                 "(IP-address host, username in the link, or lookalike characters).")

    if result.get("note"):
        st.info(result["note"])

    bar = "" if known else (f'<div class="ls-bar"><div style="width:{score * 100:.0f}%;'
                            f'background:{color}"></div></div>')
    st.markdown(
        f"""
<div class="ls-card" style="background:{bg};border-color:{border}">
  <div class="ls-eyebrow">Result</div>
  <div class="ls-level" style="color:{color}">{e(label)}</div>
  <div class="ls-score">{e(score_line)}</div>
  {bar}
  <div class="ls-fine">{e(fine)}</div>
</div>""",
        unsafe_allow_html=True,
    )

    if level != "likely_safe":
        st.markdown(f'<div class="ls-notice">{e(result["click_warning"])}</div>',
                    unsafe_allow_html=True)

    heading("Warning signs")
    signs = det.get("warning_signs") or []
    if signs:
        bullet_list(signs)
    elif known:
        bullet_list(["None found in the web address."])
    else:
        bullet_list(["No specific warning signs were found. This does not prove it is safe."])

    heading("What this means")
    st.markdown(f'<div class="ls-panel">{e(exp["explanation"])}</div>', unsafe_allow_html=True)
    if exp["source"] == "llama":
        src = f"Written by the local Llama model ({exp.get('model')})."
    elif exp["source"] == "known_site_list":
        src = "Instant answer from the built-in list of well-known sites. No model was run."
    else:
        src = ("Standard explanation. The local Llama model was unavailable, switched off, "
               "or its reply failed the safety check.")
        if exp.get("error"):
            src += f" Reason: {exp['error']}"
    st.markdown(f'<div class="ls-fine" style="margin-top:0.4rem">{e(src)}</div>',
                unsafe_allow_html=True)

    heading("What you should do")
    bullet_list(exp["advice"])

    if det.get("features"):
        with st.expander("Technical details"):
            st.json(det["features"])


def analyze_tab(kind, title, hint, multiline):
    with st.form(f"form_{kind}"):
        if multiline:
            text = st.text_area(title, height=150, placeholder=hint)
        else:
            text = st.text_input(title, placeholder=hint)
        submitted = st.form_submit_button("Check")
    key = f"result_{kind}"
    if submitted:
        with st.spinner("Checking on this computer. The explanation can take up to a minute."):
            result = service.analyze(text, forced=kind, use_llm=use_llm)
        if result["ok"]:
            history.add(result)
        st.session_state[key] = result
    if key in st.session_state:
        show_result(st.session_state[key])


# ---------------- sidebar ----------------
def status_row(color, name, message):
    return (f'<div class="ls-row"><span class="ls-dot" style="background:{color}"></span>'
            f'<div><b>{e(name)}</b><br><span class="ls-fine">{e(message)}</span></div></div>')


with st.sidebar:
    st.markdown('<div class="ls-h" style="margin-top:0">Status</div>', unsafe_allow_html=True)
    st.markdown('<div class="ls-local">Everything runs on this computer. '
                'No cloud AI and no API keys.</div>', unsafe_allow_html=True)
    status = service.model_status()
    rows = ""
    for name in ("sms", "url"):
        s = status[name]
        rows += status_row("#2F6B4B" if s["ready"] else "#A33232",
                           f"{name.upper()} detector", s["message"])
    ll = status["llama"]
    ready = bool(ll.get("server_running") and ll.get("model_installed"))
    rows += status_row("#2F6B4B" if ready else "#9A6410", "Llama explainer", ll.get("message", ""))
    st.markdown(rows, unsafe_allow_html=True)
    st.markdown(f'<div class="ls-fine">Runtime: {e(ll.get("runtime", "n/a"))}. Development only; '
                'the planned Android runtime is ExecuTorch.</div>', unsafe_allow_html=True)
    use_llm = st.checkbox("Use Llama explanation", value=ready, disabled=not ready)
    if not ready:
        st.caption("Without Llama you still get the result and a standard explanation.")

# ---------------- main page ----------------
st.markdown('<div class="ls-brand" style="margin-bottom:1rem">Local<span>Shield</span> AI</div>',
            unsafe_allow_html=True)
st.markdown('<div class="ls-notice">Do not click suspicious links or reply to suspicious '
            'messages. Paste them here instead.</div>', unsafe_allow_html=True)

tab_url, tab_sms, tab_hist = st.tabs(["Check a link", "Check a message", "History"])

with tab_url:
    analyze_tab("url", "Link", "https://example.com/login", multiline=False)

with tab_sms:
    analyze_tab("sms", "Message text", "Paste the SMS here", multiline=True)

with tab_hist:
    st.markdown(f'<div class="ls-fine">{history.count()} saved checks. Stored only on this computer; '
                'the first 300 characters of each input are kept.</div>', unsafe_allow_html=True)
    rows_h = history.recent(50)
    if rows_h:
        st.dataframe(rows_h, hide_index=True)
    confirm = st.checkbox("Confirm: delete all history")
    if st.button("Clear history", disabled=not confirm):
        history.clear()
        st.rerun()

st.markdown('<div class="ls-fine" style="margin-top:2.2rem;border-top:1px solid #E3E0D8;'
            'padding-top:0.8rem">LocalShield AI gives estimates, not guarantees. A low-risk '
            'result never proves something is safe. When in doubt, contact the sender through '
            'an official channel.</div>', unsafe_allow_html=True)