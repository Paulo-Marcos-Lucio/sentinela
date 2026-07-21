"""Renderizadores de relatório: terminal, Markdown, HTML e JSON."""

from sentinela.report.console import render_console
from sentinela.report.html import render_html
from sentinela.report.json_report import render_json
from sentinela.report.markdown import render_markdown

__all__ = ["render_console", "render_html", "render_json", "render_markdown"]
