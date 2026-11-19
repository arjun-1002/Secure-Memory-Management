"""
GUI Styling & Theme Configuration for CustomTkinter
"""

import customtkinter as ctk

# Set appearance mode and default color theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

THEME = {
    "bg_dark": "#0b0f19",
    "surface": "#111827",
    "card": "#1f2937",
    "card_hover": "#374151",
    "primary": "#6366f1",
    "primary_hover": "#4f46e5",
    "secondary": "#3b82f6",
    "success": "#10b981",
    "success_hover": "#059669",
    "danger": "#ef4444",
    "danger_hover": "#dc2626",
    "warning": "#f59e0b",
    "text": "#f9fafb",
    "text_muted": "#9ca3af",
    "border": "#374151"
}

FONT_FAMILY = "Segoe UI"
