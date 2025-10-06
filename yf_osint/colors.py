"""Terminal renk yardımcıları."""
from __future__ import annotations



class Colors:
    """Terminal çıktıları için merkezi renklendirme yardımcı sınıfı."""

    RED = "[91m"
    GREEN = "[92m"
    YELLOW = "[93m"
    BLUE = "[94m"
    PURPLE = "[95m"
    CYAN = "[96m"
    WHITE = "[97m"
    BOLD = "[1m"
    UNDERLINE = "[4m"
    RESET = "[0m"

    SUCCESS_SYMBOL = "✅"
    ERROR_SYMBOL = "❌"
    WARNING_SYMBOL = "⚠️"
    INFO_SYMBOL = "ℹ️"
    HEADER_SYMBOL = "◆"

    @classmethod
    def _format_text(cls, color_code: str, text: str, symbol: str | None = None) -> str:
        """Belirtilen rengi uygular; varsa simgeyi ekler."""
        decorated = f"{color_code}{text}{cls.RESET}"
        if symbol:
            return f"{color_code}{symbol} {text}{cls.RESET}"
        return decorated

    @classmethod
    def success(cls, text: str) -> str:
        return cls._format_text(cls.GREEN, text, cls.SUCCESS_SYMBOL)

    @classmethod
    def error(cls, text: str) -> str:
        return cls._format_text(cls.RED, text, cls.ERROR_SYMBOL)

    @classmethod
    def warning(cls, text: str) -> str:
        return cls._format_text(cls.YELLOW, text, cls.WARNING_SYMBOL)

    @classmethod
    def info(cls, text: str) -> str:
        return cls._format_text(cls.CYAN, text, cls.INFO_SYMBOL)

    @classmethod
    def header(cls, text: str) -> str:
        return cls._format_text(f"{cls.BOLD}{cls.CYAN}", text, cls.HEADER_SYMBOL)

    @classmethod
    def red(cls, text: str) -> str:
        return cls._format_text(cls.RED, text)

    @classmethod
    def green(cls, text: str) -> str:
        return cls._format_text(cls.GREEN, text)

    @classmethod
    def yellow(cls, text: str) -> str:
        return cls._format_text(cls.YELLOW, text)

    @classmethod
    def blue(cls, text: str) -> str:
        return cls._format_text(cls.BLUE, text)

    @classmethod
    def purple(cls, text: str) -> str:
        return cls._format_text(cls.PURPLE, text)

    @classmethod
    def cyan(cls, text: str) -> str:
        return cls._format_text(cls.CYAN, text)

    @classmethod
    def white(cls, text: str) -> str:
        return cls._format_text(cls.WHITE, text)

    @classmethod
    def bold(cls, text: str) -> str:
        return cls._format_text(cls.BOLD, text)

    @classmethod
    def underline(cls, text: str) -> str:
        return cls._format_text(cls.UNDERLINE, text)

    @classmethod
    def bold_red(cls, text: str) -> str:
        return cls._format_text(f"{cls.BOLD}{cls.RED}", text)

    @classmethod
    def bold_green(cls, text: str) -> str:
        return cls._format_text(f"{cls.BOLD}{cls.GREEN}", text)

    @classmethod
    def bold_yellow(cls, text: str) -> str:
        return cls._format_text(f"{cls.BOLD}{cls.YELLOW}", text)

    @classmethod
    def bold_blue(cls, text: str) -> str:
        return cls._format_text(f"{cls.BOLD}{cls.BLUE}", text)

    @classmethod
    def bold_cyan(cls, text: str) -> str:
        return cls._format_text(f"{cls.BOLD}{cls.CYAN}", text)

    @classmethod
    def separator(cls, char: str = "=", length: int = 60) -> str:
        return cls._format_text(cls.CYAN, char * length)

    @classmethod
    def title(cls, text: str) -> str:
        return cls._format_text(f"{cls.BOLD}{cls.WHITE}", text.upper())

    @classmethod
    def highlight(cls, text: str) -> str:
        return cls._format_text(f"{cls.BOLD}{cls.CYAN}", text)

    @classmethod
    def muted(cls, text: str) -> str:
        return cls._format_text(f"[90m", text)

