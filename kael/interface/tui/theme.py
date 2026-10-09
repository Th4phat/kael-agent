"""Kael's default Textual theme: near-black with a green primary.

Every colour in the stylesheet is a ``$variable`` derived from this theme,
so any built-in theme (``ctrl+p`` → "Change theme") restyles the whole UI.
"""

from textual.theme import Theme


KAEL_THEME = Theme(
    name="kael",
    primary="#22c55e",
    secondary="#16a34a",
    accent="#fbbf24",
    success="#22c55e",
    warning="#f59e0b",
    error="#ef4444",
    foreground="#d4d4d4",
    background="#0a0a0a",
    surface="#141414",
    panel="#1c1c1c",
    dark=True,
    variables={
        # Textual derives border-blurred from surface, which is invisible
        # on a near-black background.
        "border-blurred": "#333333",
        "footer-key-foreground": "#22c55e",
        "block-cursor-background": "#166534",
        "block-cursor-foreground": "#f0fdf4",
        "input-selection-background": "#22c55e 35%",
    },
)
