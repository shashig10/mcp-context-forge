# -*- coding: utf-8 -*-
"""Location: ./plugins/auth_header_injector/auth_header_injector.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Shashi Kumar <shashi.kumar@merckgroup.com>

Auth Header Injector Plugin.

This plugin injects custom authentication headers (like Authorization, API keys, tokens)
into HTTP requests based on URL path patterns. It allows you to configure different
headers for different URL paths, making it easy to add authentication to specific
endpoints without modifying application code.

Use Cases:
- Add Bearer tokens to specific API endpoints
- Inject API keys for external service calls
- Add custom authentication headers per URL pattern
- Support multiple authentication schemes for different paths

Hook: http_pre_request
"""

# Future
from __future__ import annotations

# Standard
import asyncio
import logging
import re
import time
from typing import Dict

# Third-Party
from pydantic import BaseModel, Field

# First-Party
from mcpgateway.plugins.framework import (
    HttpHeaderPayload,
    HttpPreRequestPayload,
    Plugin,
    PluginConfig,
    PluginContext,
    PluginResult,
)

# API-key specific
from typing import Optional, Dict, List
import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
import httpx

logger = logging.getLogger(__name__)


TABLE_NAME = "agentcore"
NAMESPACE_GSI_NAME = "namespace-index"
DYNAMODB_REGION = "eu-central-1"

# Initialize DynamoDB resource (reused across requests)
dynamodb = boto3.resource("dynamodb", region_name=DYNAMODB_REGION)
table = dynamodb.Table(TABLE_NAME)

class PathHeaderMapping(BaseModel):
    """Configuration for a URL path pattern and its associated headers.

    Attributes:
        pattern: URL path pattern (supports wildcards * and regex).
        headers: Dictionary of headers to inject for matching paths.
        description: Optional description of this mapping.
    """

    pattern: str = Field(..., description="URL path pattern (supports wildcards * and regex)")
    headers: Dict[str, str] = Field(default_factory=dict, description="Headers to inject")
    description: str | None = Field(None, description="Optional description")


class AuthHeaderInjectorConfig(BaseModel):
    """Configuration for auth header injection.

    Attributes:
        url_path_patterns: List of path patterns with their associated headers.
        headers: Global headers to inject for all requests (optional).
        case_sensitive: Whether URL path matching should be case-sensitive.
        bearer_token_ttl_seconds: TTL for bearer token cache in seconds (default: 3000 = 50 minutes).
        namespace_ttl_seconds: TTL for namespace record cache in seconds (default: 600 = 10 minutes).
    """

    url_path_patterns: list[PathHeaderMapping] = Field(
        default_factory=list, description="List of URL path patterns with headers to inject"
    )
    headers: Dict[str, str] = Field(default_factory=dict, description="Global headers for all requests")
    case_sensitive: bool = Field(default=False, description="Case-sensitive path matching")
    bearer_token_ttl_seconds: float = Field(
        default=3000.0,
        description="TTL for bearer token cache in seconds (default: 3000 = 50 minutes)",
        gt=0
    )
    namespace_ttl_seconds: float = Field(
        default=600.0,
        description="TTL for namespace record cache in seconds (default: 600 = 10 minutes)",
        gt=0
    )

def _get_record_by_namespace_sync(
    namespace: str,
    active_only: bool = False,
) -> Optional[Dict]:
    """
    Synchronous helper to retrieve record by namespace.
    
    Args:
        namespace: The namespace string to search for.
        active_only: If True, only return "active" items
                     (is_active is True or not set).

    Returns:
        A normalized dict representing the record, or None if not found.
    """
    try:
        logger.debug(f"Getting record {namespace}")
        key_expr = Key("namespace").eq(namespace)
        response = table.query(
            IndexName=NAMESPACE_GSI_NAME,
            KeyConditionExpression=key_expr,
            Limit=1,
        )
        items = response.get("Items", [])
        if not items:
            return None

        item = items[0]

        # Map to desired shape
        return {
            "uid": item.get("uid"),
            "role": item.get("role"),
            "tools": item.get("tools", []),
            "namespace": item.get("namespace"),
            "usecase": item.get("usecase"),
            "usecase_id": item.get("usecase_id"),
            "description": item.get("description", ""),
            "is_active": item.get("is_active", True),
            "user_pool_id": item.get("user_pool_id", ""),
            "client_id": item.get("client_id", ""),
        }

    except ClientError as e:
        logger.error(f"Error getting record by namespace: {e}")
        raise


async def get_record_by_namespace(
    namespace: str,
    active_only: bool = False,
) -> Optional[Dict]:
    """
    Async wrapper to retrieve the first record matching the provided namespace via the GSI.

    Args:
        namespace: The namespace string to search for.
        active_only: If True, only return "active" items
                     (is_active is True or not set).

    Returns:
        A normalized dict representing the record, or None if not found.
    """
    return await asyncio.to_thread(_get_record_by_namespace_sync, namespace, active_only)

class AuthHeaderInjectorPlugin(Plugin):
    """Plugin that injects authentication headers based on URL path patterns.

    This plugin runs in the HTTP middleware layer before authentication
    and injects configured headers for requests matching specific URL paths.
    """

    def __init__(self, config: PluginConfig) -> None:
        """Initialize the auth header injector plugin.

        Args:
            config: Plugin configuration.
        """
        super().__init__(config)
        self._cfg = AuthHeaderInjectorConfig(**(config.config or {}))

        # Compile regex patterns for efficient matching
        self._compiled_patterns: list[tuple[re.Pattern, Dict[str, str], str | None]] = []
        for mapping in self._cfg.url_path_patterns:
            # Convert wildcard pattern to regex
            pattern_str = mapping.pattern
            if "*" in pattern_str and not pattern_str.startswith("^"):
                # Simple wildcard pattern - convert to regex
                pattern_str = pattern_str.replace("*", ".*")
                pattern_str = f"^{pattern_str}$"

            flags = 0 if self._cfg.case_sensitive else re.IGNORECASE
            compiled = re.compile(pattern_str, flags)
            self._compiled_patterns.append((compiled, mapping.headers, mapping.description))

        # Initialize caches for bearer tokens and namespace records
        # Cache structure: {key: (value, expiry_timestamp)}
        self._bearer_token_cache: Dict[str, tuple[str, float]] = {}
        self._namespace_cache: Dict[str, tuple[Dict, float]] = {}
        
        # Cache TTL in seconds from configuration
        self._bearer_token_ttl: float = self._cfg.bearer_token_ttl_seconds
        self._namespace_ttl: float = self._cfg.namespace_ttl_seconds

        logger.error(
            f"AuthHeaderInjectorPlugin initialized with {len(self._compiled_patterns)} path patterns, "
            f"{len(self._cfg.headers)} global headers, "
            f"bearer_token_ttl={self._bearer_token_ttl}s, namespace_ttl={self._namespace_ttl}s"
        )

    def _matches_pattern(self, path: str) -> list[tuple[Dict[str, str], str | None]]:
        """Check if the path matches any configured patterns.

        Args:
            path: The URL path to check.

        Returns:
            List of (headers, description) tuples for all matching patterns.
        """
        matches = []
        for pattern, headers, description in self._compiled_patterns:
            if pattern.match(path):
                matches.append((headers, description))
        logger.error(f"AuthHeaderInjectorPlugin Path '{path}' matched patterns: {matches}")
        return matches

    def extract_nameSpace(self, url: str) -> str:
        """Extract namespace from the given URL.

        Args:
            url: The URL string to extract the namespace from.
        Returns:
            The extracted namespace as a string.
        """
        decoded = url.replace("%3A", ":").replace("%2F", "/")
        parts = decoded.split("/")
        runtime = parts[-2]
        return runtime

    async def get_bearer_token(self, uid: str) -> str:
        """
        Retrieve bearer token for the given UID with caching.

        Args:
            uid: The UID to get the bearer token for.
        Returns:
            The bearer token as a string.
        """
        current_time = time.time()
        
        # Check cache first
        if uid in self._bearer_token_cache:
            cached_token, expiry = self._bearer_token_cache[uid]
            if current_time < expiry:
                logger.error(f"Using cached bearer token for uid: {uid}")
                return cached_token
            else:
                logger.error(f"Bearer token cache expired for uid: {uid}")
        
        # Fetch new token
        BASE_URL = "https://api.nlp.dev.uptimize.merckgroup.com"
        headers = {"api-key": uid, "content-type": "application/json"}
        
        async with httpx.AsyncClient() as client:
            response = await client.post(f"{BASE_URL}/aws/runtime/bearer", headers=headers)
            response.raise_for_status()
            token = response.json()["AccessToken"]
        
        # Cache the token with expiry
        expiry_time = current_time + self._bearer_token_ttl
        self._bearer_token_cache[uid] = (token, expiry_time)
        logger.error(f"Cached bearer token for uid: {uid}, expires at: {expiry_time}")
        
        return token




    async def tool_pre_invoke(
        self,
        payload: HttpPreRequestPayload,
        context: PluginContext,
    ) -> PluginResult[HttpHeaderPayload]:
        """Inject authentication headers before tool invocation.

        This hook runs in the middleware layer BEFORE tool invocation.
        It injects headers based on URL path patterns.

        Args:
            payload: HTTP pre-request payload with headers.
            context: Plugin execution context.
        Returns:
            Result with modified headers if any patterns match.
        """

        headers: dict[str, str] = payload.headers.model_dump() if payload.headers else {}

        URL = context.dict().get("global_context").get("metadata").get("tool").get("url")

        runtime = self.extract_nameSpace(str(URL))
        namespace = runtime.split("-")[0]
        
        # Check namespace cache first
        current_time = time.time()
        if namespace in self._namespace_cache:
            cached_record, expiry = self._namespace_cache[namespace]
            if current_time < expiry:
                logger.debug(f"Using cached namespace record for: {namespace}")
                record = cached_record
            else:
                logger.debug(f"Namespace cache expired for: {namespace}")
                record = await get_record_by_namespace(namespace)
                self._namespace_cache[namespace] = (record, current_time + self._namespace_ttl)
        else:
            record = await get_record_by_namespace(namespace)
            self._namespace_cache[namespace] = (record, current_time + self._namespace_ttl)
        
        uid = record.get("uid")

        bearer_token = await self.get_bearer_token(uid)

        # logger.error(f"AuthHeaderInjectorPlugin tool_pre_invoke fetched bearer token - {bearer_token}")

        headers["Authorization"] = f"Bearer {bearer_token}"

        payload.headers = HttpHeaderPayload(root=headers)

        return PluginResult(
            modified_payload=payload,
            continue_processing=True,
        )
