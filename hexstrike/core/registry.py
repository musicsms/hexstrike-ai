from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Any

@dataclass
class ToolSpec:
    name: str
    category: str
    description: str
    endpoint: str
    handler: Callable
    parameters: Dict[str, Any] = field(default_factory=dict)
    timeout: int = 300

class ToolRegistry:
    _tools: Dict[str, ToolSpec] = {}

    @classmethod
    def register(cls, name: str, category: str, description: str, endpoint: Optional[str] = None, parameters: Optional[Dict[str, Any]] = None, timeout: int = 300):
        def decorator(func: Callable):
            tool_endpoint = endpoint or f"/api/tools/{name.replace('_', '-')}"
            spec = ToolSpec(
                name=name,
                category=category,
                description=description,
                endpoint=tool_endpoint,
                handler=func,
                parameters=parameters or {},
                timeout=timeout
            )
            cls._tools[name] = spec
            return func
        return decorator

    @classmethod
    def get(cls, name: str) -> Optional[ToolSpec]:
        return cls._tools.get(name)

    @classmethod
    def get_all_tools(cls) -> List[ToolSpec]:
        return list(cls._tools.values())

    @classmethod
    def get_by_category(cls, category: str) -> List[ToolSpec]:
        return [t for t in cls._tools.values() if t.category == category]

    @classmethod
    def clear(cls):
        cls._tools.clear()
