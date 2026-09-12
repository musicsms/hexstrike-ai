import inspect
import logging
from flask import Flask, request, jsonify
from hexstrike.core.registry import ToolRegistry, ToolSpec
from hexstrike.core.logging_config import configure_logging
from hexstrike.api.routes import api_bp
import hexstrike.tools  # Ensure all tools are imported and registered

logger = logging.getLogger(__name__)

def create_tool_view(spec: ToolSpec):
    accepted_params = set(inspect.signature(spec.handler).parameters)

    def tool_view():
        if request.method == "POST":
            payload = request.get_json(silent=True) or {}
        else:
            payload = request.args.to_dict()

        # Callers (older/legacy MCP clients, agents guessing at parameters
        # like "use_recovery" from the pre-refactor monolith's FailureRecoverySystem)
        # sometimes send fields this tool doesn't accept. Drop them instead of
        # a hard 400 so the actual scan still runs.
        unknown = {k: payload.pop(k) for k in list(payload) if k not in accepted_params}
        if unknown:
            logger.warning("Ignoring unsupported params for %s: %s", spec.name, sorted(unknown))

        try:
            result = spec.handler(**payload)
            if unknown:
                result = dict(result)
                result["ignored_params"] = sorted(unknown)
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
