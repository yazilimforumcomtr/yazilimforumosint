#!/usr/bin/env python3
"""Web entrypoint for the modular YF OSINT platform."""

import os

from yf_osint.platform import YFOSINTPlatform


def main() -> None:
    """Launch the YF OSINT web application."""
    host = os.environ.get("YF_OSINT_HOST", "127.0.0.1")
    port = int(os.environ.get("YF_OSINT_PORT", "5050"))
    debug = os.environ.get("YF_OSINT_DEBUG", "0") == "1"
    auto_open = os.environ.get("YF_OSINT_OPEN_BROWSER", "1") == "1"

    platform = YFOSINTPlatform()
    platform.run(host=host, port=port, debug=debug, open_browser=auto_open)


if __name__ == "__main__":
    main()
