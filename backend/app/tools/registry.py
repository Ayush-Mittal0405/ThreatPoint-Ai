"""
Tool Registry — central registry for all agent tools.

Every tool call is routed through here for:
- Authorization (read vs write classification)
- Input validation
- Logging
- Error handling
"""
from __future__ import annotations

from typing import Any, Dict

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.tools.search_tools import SearchTools
from app.tools.intel_tools import IntelTools
from app.tools.knowledge_tools import KnowledgeTools

log = structlog.get_logger()

# Tools that are ALWAYS read-only and safe for autonomous use
READ_ONLY_TOOLS = {
    "search_endpoint_events",
    "search_process_tree",
    "search_network_events",
    "search_user_activity",
    "lookup_ip",
    "lookup_domain",
    "lookup_hash",
    "search_mitre_technique",
    "search_rag",
    "query_attack_graph",
    "search_historical_incidents",
}

# Tools that require human approval
WRITE_TOOLS = {
    "isolate_lab_endpoint",
    "kill_lab_process",
    "quarantine_lab_file",
    "block_lab_ioc",
    "disable_lab_account",
}


class ToolRegistry:
    """
    Central tool dispatcher with authorization checks.
    Investigation agents can only call READ_ONLY_TOOLS.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self._search = SearchTools(db)
        self._intel = IntelTools()
        self._knowledge = KnowledgeTools(db)

    async def call(self, tool_name: str, args: Dict) -> Any:
        """
        Execute a tool by name.
        Raises PermissionError if a write tool is called without approval.
        """
        if tool_name in WRITE_TOOLS:
            raise PermissionError(
                f"Tool '{tool_name}' requires human approval. "
                "Use the response approval workflow."
            )

        if tool_name not in READ_ONLY_TOOLS:
            log.warning("Unknown tool requested", tool=tool_name)
            return {"error": f"Unknown tool: {tool_name}"}

        log.info("Tool call", tool=tool_name, args=args)
        return await self._dispatch(tool_name, args)

    async def _dispatch(self, tool_name: str, args: Dict) -> Any:
        """Route to the correct tool implementation."""
        try:
            # Search tools
            if tool_name == "search_endpoint_events":
                return await self._search.search_endpoint_events(**args)
            elif tool_name == "search_process_tree":
                return await self._search.search_process_tree(**args)
            elif tool_name == "search_network_events":
                return await self._search.search_network_events(**args)
            elif tool_name == "search_user_activity":
                return await self._search.search_user_activity(**args)
            elif tool_name == "search_historical_incidents":
                return await self._search.search_historical_incidents(**args)

            # Intelligence tools
            elif tool_name == "lookup_ip":
                return await self._intel.lookup_ip(**args)
            elif tool_name == "lookup_domain":
                return await self._intel.lookup_domain(**args)
            elif tool_name == "lookup_hash":
                return await self._intel.lookup_hash(**args)

            # Knowledge tools
            elif tool_name == "search_mitre_technique":
                return await self._knowledge.search_mitre_technique(**args)
            elif tool_name == "search_rag":
                return await self._knowledge.search_rag(**args)
            elif tool_name == "query_attack_graph":
                return await self._knowledge.query_attack_graph(**args)

            else:
                return {"error": f"Unimplemented tool: {tool_name}"}

        except TypeError as exc:
            log.warning("Tool argument error", tool=tool_name, error=str(exc))
            return {"error": f"Invalid arguments for {tool_name}: {exc}"}
        except Exception as exc:
            log.exception("Tool execution error", tool=tool_name, error=str(exc))
            return {"error": f"Tool error: {exc}"}
