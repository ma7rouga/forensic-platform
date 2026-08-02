

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

.stApp {
    background-image:
        linear-gradient(var(--cw-border) 1px, transparent 1px),
        linear-gradient(90deg, var(--cw-border) 1px, transparent 1px);
    background-size: 42px 42px;
    background-position: center;
    background-color: var(--cw-bg);
}
.stApp::before {
    content: "";
    position: fixed;
    inset: 0;
    background: radial-gradient(ellipse at top, rgba(16,18,20,0) 0%, var(--cw-bg) 75%);
    pointer-events: none;
    z-index: 0;
}

h1, h2, h3 {
    font-family: 'Space Grotesk', sans-serif !important;
    font-weight: 600 !important;
    letter-spacing: -0.01em;
}

.stJson, code, pre {
    font-family: 'JetBrains Mono', monospace !important;
}

.stButton > button {
    background-color: transparent;
    color: var(--cw-amber);
    border: 1px solid var(--cw-amber-dim);
    border-radius: 5px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12.5px;
    font-weight: 500;
    padding: 0.4rem 1rem;
    transition: border-color 0.15s ease;
}
.stButton > button:hover {
    border-color: var(--cw-amber);
    color: var(--cw-amber);
}

section[data-testid="stSidebar"] {
    border-right: 1px solid var(--cw-border);
    background-color: var(--cw-panel);
}

.stTabs [data-baseweb="tab-list"] {
    gap: 28px;
    border-bottom: 1px solid var(--cw-border);
}
.stTabs [data-baseweb="tab"] {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 13px;
    color: var(--cw-muted);
    padding-bottom: 10px;
}
.stTabs [aria-selected="true"] {
    color: var(--cw-text) !important;
    border-bottom-color: var(--cw-amber) !important;
}

.cw-eyebrow {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: var(--cw-muted-2);
    letter-spacing: 0.5px;
    text-transform: uppercase;
    margin-bottom: 4px;
}

.cw-real-marker, .cw-mock-marker {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11.5px;
    color: var(--cw-muted);
    margin-bottom: 6px;
}
.cw-real-marker::before {
    content: '';
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--cw-green);
    box-shadow: 0 0 6px var(--cw-green);
}
.cw-mock-marker::before {
    content: '';
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--cw-muted-2);
}

/* Top status strip — tool availability, one line, no clutter */
.cw-status-strip {
    display: flex;
    gap: 22px;
    padding: 10px 0 18px 0;
    margin-bottom: 6px;
    border-bottom: 1px solid var(--cw-border);
    flex-wrap: wrap;
}
.cw-status-item {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: var(--cw-muted);
    display: flex;
    align-items: center;
    gap: 6px;
}
.cw-status-item::before {
    content: '';
    width: 5px;
    height: 5px;
    border-radius: 50%;
}
.cw-status-item.on::before { background: var(--cw-green); box-shadow: 0 0 5px var(--cw-green); }
.cw-status-item.off::before { background: var(--cw-muted-2); }

/* Metric cards — used at the top of the Report tab */
.cw-metric-row {
    display: flex;
    gap: 14px;
    margin-bottom: 22px;
}
.cw-metric {
    flex: 1;
    background: var(--cw-panel);
    border: 1px solid var(--cw-border);
    border-radius: 6px;
    padding: 14px 16px;
}
.cw-metric-value {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 22px;
    font-weight: 600;
    color: var(--cw-text);
}
.cw-metric-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 10.5px;
    color: var(--cw-muted);
    text-transform: uppercase;
    letter-spacing: 0.4px;
    margin-top: 2px;
}

.cw-finding {
    padding: 12px 0;
    border-top: 1px solid var(--cw-border);
}
.cw-finding:last-child { border-bottom: 1px solid var(--cw-border); }
.cw-finding-top { display: flex; justify-content: space-between; margin-bottom: 4px; }
.cw-finding-label { font-size: 13px; font-weight: 500; color: var(--cw-text); }
.cw-finding-sev { font-family: 'JetBrains Mono', monospace; font-size: 10.5px; color: var(--cw-red); }
.cw-finding-sev.warn { color: var(--cw-amber); }
.cw-finding-detail { font-size: 12px; color: var(--cw-muted); line-height: 1.55; }
.cw-finding-conf { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--cw-muted-2); margin-top: 6px; }
</style>
"""


def inject_theme():
    st.markdown(CSS, unsafe_allow_html=True)


def real_marker(text: str = "live result"):
    st.markdown(f'<span class="cw-real-marker">{text}</span>', unsafe_allow_html=True)


def mock_marker(text: str = "sample data"):
    st.markdown(f'<span class="cw-mock-marker">{text}</span>', unsafe_allow_html=True)


def status_strip(items: list[tuple[str, bool]]):
    """items: list of (label, is_live) e.g. [("Volatility3", True), ("Ghidra", False)]"""
    spans = "".join(
        f'<div class="cw-status-item {"on" if live else "off"}">{label}</div>'
        for label, live in items
    )
    st.markdown(f'<div class="cw-status-strip">{spans}</div>', unsafe_allow_html=True)


def metric_row(metrics: list[tuple[str, str]]):
    """metrics: list of (value, label) e.g. [("14", "processes"), ("3", "findings")]"""
    cards = "".join(
        f'<div class="cw-metric"><div class="cw-metric-value">{value}</div>'
        f'<div class="cw-metric-label">{label}</div></div>'
        for value, label in metrics
    )
    st.markdown(f'<div class="cw-metric-row">{cards}</div>', unsafe_allow_html=True)


def finding(label: str, severity: str, detail: str, confidence: int = None, warn: bool = False):
    sev_class = "cw-finding-sev warn" if warn else "cw-finding-sev"
    conf_html = f'<div class="cw-finding-conf">confidence {confidence}%</div>' if confidence is not None else ""
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