#!/usr/bin/env python3
"""The product tools, shared by both transports.

The tools themselves are identical whether the server runs locally over stdio or
remotely over HTTP; only where the bearer token comes from differs. stdio reads a
token cached by its own browser login (auth.py), while the remote server is an
OAuth resource server and forwards the token Claude Code presents on the request.

`register_products` takes that difference as a parameter, so neither transport
holds a second copy of the API calls.
"""

from __future__ import annotations

import os
from typing import Annotated, Any, Awaitable, Callable

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

BASE_URL = os.environ.get("CRUD_API_BASE_URL", "http://localhost:8090").rstrip("/")
TIMEOUT = float(os.environ.get("CRUD_API_TIMEOUT", "10"))

Price = Annotated[float, Field(ge=0, description="Price; must be zero or greater")]
Name = Annotated[str, Field(min_length=1, description="Product name; must not be blank")]
ProductId = Annotated[int, Field(gt=0, description="Product id")]
Description = Annotated[str | None, Field(description="Optional free-text description")]

# Given force_refresh, returns a bearer token for the signed in user.
TokenProvider = Callable[[bool], Awaitable[str]]


def register_products(mcp: MCPServer, token_provider: TokenProvider) -> None:
    """Add the six product tools to `mcp`, authenticating with `token_provider`."""

    async def call(method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        """Call the service and translate failures into MCP tool errors."""
        try:
            async with httpx.AsyncClient(base_url=BASE_URL, timeout=TIMEOUT) as client:
                headers = {"Authorization": f"Bearer {await token_provider(False)}"}
                response = await client.request(method, path, json=body, headers=headers)

                # A cached token rejected by the server (restart, rotated key) is retried once.
                if response.status_code == 401:
                    headers = {"Authorization": f"Bearer {await token_provider(True)}"}
                    response = await client.request(method, path, json=body, headers=headers)
        except httpx.RequestError as exc:
            raise ToolError(f"Cannot reach the product service at {BASE_URL}: {exc}") from exc

        payload: Any = None
        if response.content:
            try:
                payload = response.json()
            except ValueError:
                payload = response.text

        if response.is_error:
            detail = "no response body"
            if isinstance(payload, dict):
                detail = payload.get("detail") or payload.get("error") or detail
                if errors := payload.get("errors"):
                    detail = f"{detail} {errors}"
            elif payload:
                detail = str(payload)
            raise ToolError(f"{method} {path} failed (HTTP {response.status_code}): {detail}")

        return payload if payload is not None else {"status": response.status_code}

    @mcp.tool(title="List products", description="List every product in the catalogue.")
    async def list_products() -> list[dict[str, Any]]:
        return await call("GET", "/api/products")

    @mcp.tool(
        title="Get product",
        description="Fetch a single product by id. Errors if no such product exists.",
    )
    async def get_product(id: ProductId) -> dict[str, Any]:
        return await call("GET", f"/api/products/{id}")

    @mcp.tool(
        title="Create product",
        description="Create a new product and return it with its assigned id.",
    )
    async def create_product(
        name: Name, price: Price, description: Description = None
    ) -> dict[str, Any]:
        return await call(
            "POST", "/api/products", {"name": name, "description": description, "price": price}
        )

    @mcp.tool(
        title="Update product",
        description="Replace an existing product. Omitted optional fields are cleared.",
    )
    async def update_product(
        id: ProductId, name: Name, price: Price, description: Description = None
    ) -> dict[str, Any]:
        return await call(
            "PUT", f"/api/products/{id}",
            {"name": name, "description": description, "price": price},
        )

    @mcp.tool(title="Delete product", description="Delete a product by id.")
    async def delete_product(id: ProductId) -> dict[str, Any]:
        await call("DELETE", f"/api/products/{id}")
        return {"deleted": id}

    @mcp.tool(
        title="Health check",
        description="Report the health of the product service and its database.",
    )
    async def health_check() -> dict[str, Any]:
        return await call("GET", "/actuator/health")
