import time
import shutil
from flask import Blueprint, jsonify, request
from hexstrike import __version__
from hexstrike.core.registry import ToolRegistry
from hexstrike.core.process import default_process_manager

api_bp = Blueprint("system_api", __name__)
START_TIME = time.time()

@api_bp.route("/health", methods=["GET"])
@api_bp.route("/api/health", methods=["GET"])
def health_check():
    all_tools = ToolRegistry.get_all_tools()
    tools_status = {
        spec.name: (shutil.which(spec.name.split("_")[0]) is not None)
        for spec in all_tools
    }
    available_count = sum(1 for status in tools_status.values() if status)

    return jsonify({
        "status": "healthy",
        "message": "HexStrike AI Tools API Server is operational",
        "version": __version__,
        "uptime": time.time() - START_TIME,
        "all_essential_tools_available": True,
        "total_tools_count": len(all_tools),
        "total_tools_available": available_count,
        "tools_status": tools_status,
        "cache_stats": default_process_manager.get_cache_stats()
    })

@api_bp.route("/api/tools", methods=["GET"])
def list_tools():
    tools = [
        {
            "name": spec.name,
            "category": spec.category,
            "description": spec.description,
            "endpoint": spec.endpoint
        }
        for spec in ToolRegistry.get_all_tools()
    ]
    return jsonify({"tools": tools, "count": len(tools)})
