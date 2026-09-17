#!/usr/bin/env python3
"""Smoke test: drives server.py as a real MCP client over stdio.

Requires the Spring Boot service to be running at CRUD_API_BASE_URL.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

failures = 0


def report(label: str, result, expect_error: bool = False) -> str:
    global failures
    text = "\n".join(getattr(c, "text", "") for c in result.content)
    bad = bool(result.is_error) != expect_error
    if bad:
        failures += 1
    indented = text.replace("\n", "\n      ")
    print(f"{'FAIL' if bad else 'ok  '}  {label}\n      {indented}")
    return text


async def main() -> int:
    params = StdioServerParameters(
        command=sys.executable,
        args=["server.py"],
        env={**os.environ},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = (await session.list_tools()).tools
            print(f"tools ({len(tools)}): {', '.join(t.name for t in tools)}\n")

            async def call(tool, /, **args):
                return await session.call_tool(tool, args)

            report("health_check", await call("health_check"))
            created = report(
                "create_product",
                await call("create_product", name="Keyboard", description="Mechanical", price=129.0),
            )
            pid = json.loads(created)["id"]

            report("get_product", await call("get_product", id=pid))
            report("list_products", await call("list_products"))
            report(
                "update_product",
                await call("update_product", id=pid, name="Keyboard Pro", description="Hot-swap", price=179.0),
            )
            report("get_product (after update)", await call("get_product", id=pid))
            report("delete_product", await call("delete_product", id=pid))
            report("get_product (deleted -> error)", await call("get_product", id=pid), True)
            report("create_product (invalid -> error)", await call("create_product", name="", price=-5), True)

    print(f"\n{'ALL CHECKS PASSED' if failures == 0 else f'{failures} CHECK(S) FAILED'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
