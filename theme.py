"""
theme.py

Injects the approved visual direction (restrained dark theme, Space Grotesk
headers, JetBrains Mono for technical data) into the Streamlit app.

Usage in app.py:
    from theme import inject_theme
    inject_theme()
    # ... rest of app.py unchanged

This only affects appearance — it doesn't touch any pipeline logic, session
state, or button behavior. Safe to drop in without breaking existing tabs.
"""

import streamlit as st

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');

:root{
    --cw-bg: #101214;
    --cw-panel: #16191C;
    --cw-border: #24272B;
    --cw-text: #E4E6E8;
    --cw-muted: #7C838C;
    --cw-muted-2: #4D525A;
    --cw-amber: #D99A45;
    --cw-amber-dim: #2E2717;
    --cw-green: #4E9A7D;
    --cw-red: #B9564F;
}

/* Headings use the display face; body text stays readable */
h1, h2, h3 {
    font-family: 'Space Grotesk', sans-serif !important;
    font-weight: 600 !important;
}

/* Technical/data output (json, code) always in mono */
.stJson, code, pre {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Quiet the default Streamlit button — no bright blue, no heavy shadow */
.stButton > button {
    background-color: transparent;
    color: var(--cw-amber);
    border: 1px solid var(--cw-amber-dim);
    border-radius: 5px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12.5px;
    font-weight: 500;
    padding: 0.4rem 1rem;
}
.stButton > button:hover {
    border-color: var(--cw-amber);
    color: var(--cw-amber);
}

/* Sidebar: quiet, no loud dividers */
section[data-testid="stSidebar"] {
    border-right: 1px solid var(--cw-border);
}

/* Tabs: understated, single subtle underline on the active tab */
.stTabs [data-baseweb="tab"] {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 13px;
    color: var(--cw-muted);
}
.stTabs [aria-selected="true"] {
    color: var(--cw-text) !important;
    border-bottom-color: var(--cw-amber) !important;
}

/* Caption / eyebrow text */
.cw-eyebrow {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: var(--cw-muted-2);
    letter-spacing: 0.5px;
    margin-bottom: 4px;
}

/* Single "this is a real result" marker — used sparingly, not on every element */
.cw-real-marker {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11.5px;
    color: var(--cw-muted);
}
.cw-real-marker::before {
    content: '';
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--cw-green);
}
.cw-mock-marker {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11.5px;
    color: var(--cw-muted);
}
.cw-mock-marker::before {
    content: '';
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--cw-muted-2);
}

/* A single finding row — plain, separated by a hairline, no card/border noise */
.cw-finding {
    padding: 12px 0;
    border-top: 1px solid var(--cw-border);
}
.cw-finding:last-child {
    border-bottom: 1px solid var(--cw-border);
}
.cw-finding-top {
    display: flex;
    justify-content: space-between;
    margin-bottom: 4px;
}
.cw-finding-label {
    font-size: 13px;
    font-weight: 500;
    color: var(--cw-text);
}
.cw-finding-sev {
    font-family: 'JetBrains Mono', monospace;
    font-size: 10.5px;
    color: var(--cw-red);
}
.cw-finding-sev.warn {
    color: var(--cw-amber);
}
.cw-finding-detail {
    font-size: 12px;
    color: var(--cw-muted);
    line-height: 1.55;
}
.cw-finding-conf {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: var(--cw-muted-2);
    margin-top: 6px;
}
</style>
"""


def inject_theme():
    """Call once near the top of app.py, right after st.set_page_config()."""
    st.markdown(CSS, unsafe_allow_html=True)


def real_marker(text: str = "résultat réel"):
    """Small inline marker for genuinely real (non-mock) results."""
    st.markdown(f'<span class="cw-real-marker">{text}</span>', unsafe_allow_html=True)


def mock_marker(text: str = "résultat simulé"):
    """Small inline marker for mock/fallback results."""
    st.markdown(f'<span class="cw-mock-marker">{text}</span>', unsafe_allow_html=True)


def finding(label: str, severity: str, detail: str, confidence: int = None, warn: bool = False):
    """Renders one finding as a plain row (no card/border clutter), matching
    the approved v2 mockup — used instead of raw st.json for key results."""
    sev_class = "cw-finding-sev warn" if warn else "cw-finding-sev"
    conf_html = f'<div class="cw-finding-conf">confiance {confidence}%</div>' if confidence is not None else ""
    st.markdown(f"""
    <div class="cw-finding">
        <div class="cw-finding-top">
            <span class="cw-finding-label">{label}</span>
            <span class="{sev_class}">{severity}</span>
        </div>
        <div class="cw-finding-detail">{detail}</div>
        {conf_html}
    </div>
    """, unsafe_allow_html=True)