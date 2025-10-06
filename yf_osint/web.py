"""Flask-based web dashboard."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

try:
    from flask import Flask, jsonify, render_template, request
    FLASK_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    FLASK_AVAILABLE = False
    print("Flask not available. Web dashboard disabled.")


class WebServer:
    """Serve the modern YF OSINT web experience."""

    def __init__(self, platform: "YFOSINTPlatform") -> None:
        if not FLASK_AVAILABLE:
            raise ImportError("Flask bulunamadı. Web arayüzü kullanılamaz.")

        self.platform = platform
        root_dir = Path(__file__).resolve().parent.parent
        template_dir = root_dir / "dashboard" / "templates"
        static_dir = root_dir / "dashboard" / "static"
        template_dir.mkdir(parents=True, exist_ok=True)
        static_dir.mkdir(parents=True, exist_ok=True)

        self.app = Flask(
            __name__,
            template_folder=str(template_dir),
            static_folder=str(static_dir),
        )
        self.app.secret_key = "yf_osint_web_app_2025"
        self.app.config['JSON_AS_ASCII'] = False
        self.app.config.setdefault('TEMPLATES_AUTO_RELOAD', True)

        self._register_routes()

    # ------------------------------------------------------------------
    # Route setup
    # ------------------------------------------------------------------
    def _register_routes(self) -> None:
        """Register HTTP routes for the dashboard."""
        app = self.app

        @app.get("/")
        def index() -> str:
            catalog = self.platform.get_tool_catalog()
            stats = self.platform.get_system_snapshot()
            return render_template(
                "index.html",
                tool_catalog=catalog,
                system_stats=stats,
            )

        @app.get("/healthz")
        def healthcheck() -> Dict[str, str]:
            return {"status": "ok"}

        @app.get("/api/tools")
        def api_tools():
            return jsonify(self.platform.get_tool_catalog())

        @app.post("/api/tools/<tool_id>")
        def api_run_tool(tool_id: str):
            payload: Dict[str, Any] = request.get_json(silent=True) or {}
            try:
                result = self.platform.execute_tool(tool_id, payload)
                return jsonify({"success": True, "result": result})
            except ValueError as exc:
                return jsonify({"success": False, "error": str(exc)}), 400
            except Exception as exc:  # pragma: no cover - runtime safety
                return (
                    jsonify({"success": False, "error": str(exc)}),
                    500,
                )

        @app.get("/api/system")
        def api_system():
            return jsonify(self.platform.get_system_snapshot())

        @app.get("/api/encrypted-files")
        def api_encrypted_files():
            try:
                files = self.platform.result_manager.list_encrypted_results()
                return jsonify(files)
            except Exception as exc:  # pragma: no cover - defensive
                return jsonify({"error": str(exc)}), 500

        @app.get("/api/encrypted-files/view")
        def api_view_encrypted_file():
            file_path = request.args.get("file")
            if not file_path:
                return jsonify({"error": "Dosya yolu gerekli"}), 400
            result = self.platform.result_manager.load_encrypted_result(file_path)
            if not result:
                return jsonify({"error": "Dosya okunamadı"}), 404
            return jsonify(result)

        @app.delete("/api/encrypted-files")
        def api_delete_encrypted_file():
            file_path = request.args.get("file")
            if not file_path:
                return jsonify({"error": "Dosya yolu gerekli"}), 400
            try:
                path = Path(file_path)
                if path.exists():
                    path.unlink()
                    return jsonify({"message": "Dosya silindi"})
                return jsonify({"error": "Dosya bulunamadı"}), 404
            except Exception as exc:  # pragma: no cover - filesystem safety
                return jsonify({"error": str(exc)}), 500

        @app.delete("/api/encrypted-files/all")
        def api_clear_encrypted_files():
            try:
                count = 0
                for file_path in self.platform.result_manager.list_encrypted_results():
                    path = Path(file_path)
                    if path.exists():
                        path.unlink()
                        count += 1
                return jsonify({"message": f"{count} dosya silindi", "deleted": count})
            except Exception as exc:  # pragma: no cover - defensive
                return jsonify({"error": str(exc)}), 500

        @app.get("/api/export")
        def api_export():
            try:
                files = self.platform.result_manager.list_encrypted_results()
                payload = []
                for file_path in files:
                    data = self.platform.result_manager.load_encrypted_result(file_path)
                    if data:
                        payload.append({"file": Path(file_path).name, "data": data})
                response = app.response_class(
                    response=json.dumps(payload, indent=2, ensure_ascii=False),
                    mimetype="application/json",
                )
                response.headers[
                    "Content-Disposition"
                ] = "attachment; filename=yf_osint_export.json"
                return response
            except Exception as exc:  # pragma: no cover - defensive
                return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def start(self, host: str = "127.0.0.1", port: int = 5000, debug: bool = False) -> None:
        """Run the Flask development server."""
        self.app.run(host=host, port=port, debug=debug, use_reloader=False)
