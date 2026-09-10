from flask import Flask, request, jsonify
from hexstrike.core.registry import ToolRegistry, ToolSpec
from hexstrike.core.logging_config import configure_logging
from hexstrike.api.routes import api_bp
import hexstrike.tools  # Ensure all tools are imported and registered

def create_tool_view(spec: ToolSpec):
    def tool_view():
        if request.method == "POST":
            payload = request.get_json(silent=True) or {}
        else:
            payload = request.args.to_dict()
        try:
            result = spec.handler(**payload)
            return jsonify(result)
        except TypeError as err:
            return jsonify({
                "success": False,
                "error": f"Invalid arguments for {spec.name}: {str(err)}",
                "command": spec.name
            }), 400
        except Exception as err:
            return jsonify({
                "success": False,
                "error": str(err),
                "command": spec.name
            }), 500
    tool_view.__name__ = f"view_{spec.name}"
    return tool_view

def create_app(debug: bool = False) -> Flask:
    configure_logging()
    app = Flask("hexstrike")
    app.debug = debug

    # Register system endpoints
    app.register_blueprint(api_bp)

    # Mount dynamic tool routes
    for spec in ToolRegistry.get_all_tools():
        app.add_url_rule(
            rule=spec.endpoint,
            endpoint=f"tool_{spec.name}",
            view_func=create_tool_view(spec),
            methods=["GET", "POST"]
        )

    return app
