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
import logging
import re
import time
from collections import OrderedDict
from typing import Dict, Optional, Any, Tuple

# Third-Party
import aioboto3
import httpx
from botocore.exceptions import ClientError
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

logger = logging.getLogger(__name__)


TABLE_NAME = "agentcore"
NAMESPACE_GSI_NAME = "namespace-index"
DYNAMODB_REGION = "eu-central-1"

# Initialize aioboto3 session (for async DynamoDB access)
session = aioboto3.Session(region_name=DYNAMODB_REGION)


class TTLLRUCache:
    """
    A simple TTL-aware LRU cache implementation.

    This cache stores items with expiration times and automatically evicts
    expired entries. It uses OrderedDict for LRU behavior.
    """

    def __init__(self, maxsize: int, ttl: float):
        """
        Initialize the TTL LRU cache.

        Args:
            maxsize: Maximum number of items to store.
            ttl: Time-to-live in seconds for cached items.
        """
        self.maxsize = maxsize
        self.ttl = ttl
        self.cache: OrderedDict[str, Tuple[Any, float]] = OrderedDict()

    def get(self, key: str) -> Optional[Any]:
        """
        Get an item from the cache.

        Args:
            key: The cache key.
        Returns:
            The cached value if found and not expired, None otherwise.
        """
        if key not in self.cache:
            return None

        value, expiry = self.cache[key]
        current_time = time.time()

        if current_time >= expiry:
            # Expired, remove it
            del self.cache[key]
            return None

        # Move to end (most recently used)
        self.cache.move_to_end(key)
        return value

    def set(self, key: str, value: Any) -> None:
        """
        Set an item in the cache.

        Args:
            key: The cache key.
            value: The value to cache.
        """
        current_time = time.time()
        expiry = current_time + self.ttl

        if key in self.cache:
            # Update existing entry
            self.cache[key] = (value, expiry)
            self.cache.move_to_end(key)
        else:
            # Add new entry
            self.cache[key] = (value, expiry)

            # Evict oldest if over capacity
            if len(self.cache) > self.maxsize:
                self.cache.popitem(last=False)

    def clear(self) -> None:
        """Clear all items from the cache."""
        self.cache.clear()

    def __len__(self) -> int:
        """Return the number of items in the cache."""
        return len(self.cache)


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
        bearer_token_cache_size: Maximum size of bearer token LRU cache (default: 128).
        namespace_cache_size: Maximum size of namespace LRU cache (default: 256).
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
    bearer_token_cache_size: int = Field(
        default=128,
        description="Maximum size of bearer token LRU cache",
        gt=0
    )
    namespace_cache_size: int = Field(
        default=256,
        description="Maximum size of namespace LRU cache",
        gt=0
    )


async def get_record_by_namespace(
    namespace: str,
    active_only: bool = False,
) -> Optional[Dict]:
    """
    Async helper to retrieve record by namespace using aioboto3.

    Args:
        namespace: The namespace string to search for.
        active_only: If True, only return "active" items
                     (is_active is True or not set).

    Returns:
        A normalized dict representing the record, or None if not found.
    """
    try:
        # logger.debug(f"Getting record {namespace}")

        async with session.client("dynamodb", region_name=DYNAMODB_REGION) as dynamodb_client:
            response = await dynamodb_client.query(
                TableName=TABLE_NAME,
                IndexName=NAMESPACE_GSI_NAME,
                KeyConditionExpression="namespace = :namespace",
                ExpressionAttributeValues={
                    ":namespace": {"S": namespace}
                },
                Limit=1,
            )

            items = response.get("Items", [])
            if not items:
                return None

            item = items[0]

            # Convert DynamoDB format to Python dict
            def dynamodb_to_python(ddb_value):
                """Convert DynamoDB typed value to Python value."""
                if "S" in ddb_value:
                    return ddb_value["S"]
                elif "N" in ddb_value:
                    return float(ddb_value["N"])
                elif "BOOL" in ddb_value:
                    return ddb_value["BOOL"]
                elif "L" in ddb_value:
                    return [dynamodb_to_python(v) for v in ddb_value["L"]]
                elif "M" in ddb_value:
                    return {k: dynamodb_to_python(v) for k, v in ddb_value["M"].items()}
                elif "NULL" in ddb_value:
                    return None
                return ddb_value

            # Map to desired shape
            return {
                "uid": dynamodb_to_python(item.get("uid", {"NULL": True})),
                "role": dynamodb_to_python(item.get("role", {"NULL": True})),
                "tools": dynamodb_to_python(item.get("tools", {"L": []})),
                "namespace": dynamodb_to_python(item.get("namespace", {"NULL": True})),
                "usecase": dynamodb_to_python(item.get("usecase", {"NULL": True})),
                "usecase_id": dynamodb_to_python(item.get("usecase_id", {"NULL": True})),
                "description": dynamodb_to_python(item.get("description", {"S": ""})),
                "is_active": dynamodb_to_python(item.get("is_active", {"BOOL": True})),
                "user_pool_id": dynamodb_to_python(item.get("user_pool_id", {"S": ""})),
                "client_id": dynamodb_to_python(item.get("client_id", {"S": ""})),
            }

    except ClientError as e:
        logger.error(f"Error getting record by namespace: {e}")
        raise



class AuthHeaderInjectorPlugin(Plugin):
    """Plugin that injects authentication headers based on URL path patterns.

    This plugin runs in the HTTP middleware layer before authentication
    and injects configured headers for requests matching specific URL paths.
    Uses custom TTL-aware LRU cache for bearer tokens and namespace records.
    """

    def __init__(self, config: PluginConfig) -> None:
        """Initialize the auth header injector plugin.

        Args:
            config: Plugin configuration.
        """
        super().__init__(config)
        self._cfg = AuthHeaderInjectorConfig(**(config.config or {}))

        self._http_client = httpx.AsyncClient()

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

        # Initialize TTL-aware LRU caches
        self._bearer_token_cache = TTLLRUCache(
            maxsize=self._cfg.bearer_token_cache_size,
            ttl=self._cfg.bearer_token_ttl_seconds
        )
        self._namespace_cache = TTLLRUCache(
            maxsize=self._cfg.namespace_cache_size,
            ttl=self._cfg.namespace_ttl_seconds
        )

        # logger.error(
        #     f"AuthHeaderInjectorPlugin initialized with {len(self._compiled_patterns)} path patterns, "
        #     f"{len(self._cfg.headers)} global headers, "
        #     f"bearer_token_ttl={self._cfg.bearer_token_ttl_seconds}s (cache_size={self._cfg.bearer_token_cache_size}), "
        #     f"namespace_ttl={self._cfg.namespace_ttl_seconds}s (cache_size={self._cfg.namespace_cache_size})"
        # )

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
        logger.debug(f"AuthHeaderInjectorPlugin Path '{path}' matched {len(matches)} patterns")
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
        Retrieve bearer token for the given UID with TTL-aware LRU caching.

        Args:
            uid: The UID to get the bearer token for.
        Returns:
            The bearer token as a string.
        """
        # start_time = time.time()

        # Check cache first
        # cache_check_start = time.time()
        cached_token = self._bearer_token_cache.get(uid)
        # cache_check_duration = (time.time() - cache_check_start) * 1000  # Convert to ms

        if cached_token is not None:
            total_duration = (time.time() - start_time) * 1000
            logger.error(
                f"[LATENCY] Bearer token cache HIT for uid={uid} | "
                f"cache_check={cache_check_duration:.2f}ms, total={total_duration:.2f}ms"
            )
            return cached_token

        logger.error(f"[LATENCY] Bearer token cache MISS for uid={uid} | cache_check={cache_check_duration:.2f}ms")

        # Fetch new token
        # fetch_start = time.time()
        BASE_URL = "https://api.nlp.dev.uptimize.merckgroup.com"
        headers = {"api-key": uid, "content-type": "application/json"}

        response = await self._http_client.post(f"{BASE_URL}/aws/runtime/bearer", headers=headers)
        response.raise_for_status()
        token = response.json()["AccessToken"]

        # fetch_duration = (time.time() - fetch_start) * 1000

        # Cache the token
        # cache_set_start = time.time()
        self._bearer_token_cache.set(uid, token)
        # cache_set_duration = (time.time() - cache_set_start) * 1000

        # total_duration = (time.time() - start_time) * 1000
        # logger.error(
        #     f"[LATENCY] Bearer token fetched for uid={uid} | "
        #     f"api_call={fetch_duration:.2f}ms, cache_set={cache_set_duration:.2f}ms, total={total_duration:.2f}ms"
        # )

        return token

    async def get_namespace_record(self, namespace: str) -> Optional[Dict]:
        """
        Retrieve namespace record with TTL-aware LRU caching.

        Args:
            namespace: The namespace to get the record for.
        Returns:
            The namespace record dict or None.
        """
        start_time = time.time()

        # Check cache first
        cache_check_start = time.time()
        cached_record = self._namespace_cache.get(namespace)
        cache_check_duration = (time.time() - cache_check_start) * 1000

        if cached_record is not None:
            total_duration = (time.time() - start_time) * 1000
            logger.error(
                f"[LATENCY] Namespace cache HIT for namespace={namespace} | "
                f"cache_check={cache_check_duration:.2f}ms, total={total_duration:.2f}ms"
            )
            return cached_record

        logger.info(f"[LATENCY] Namespace cache MISS for namespace={namespace} | cache_check={cache_check_duration:.2f}ms")

        # Fetch the record
        fetch_start = time.time()
        record = await get_record_by_namespace(namespace)
        fetch_duration = (time.time() - fetch_start) * 1000

        # Cache the record
        cache_set_start = time.time()
        if record is not None:
            self._namespace_cache.set(namespace, record)
        cache_set_duration = (time.time() - cache_set_start) * 1000

        total_duration = (time.time() - start_time) * 1000
        logger.error(
            f"[LATENCY] Namespace record fetched for namespace={namespace} | "
            f"dynamodb_query={fetch_duration:.2f}ms, cache_set={cache_set_duration:.2f}ms, total={total_duration:.2f}ms"
        )

        return record

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
        plugin_start_time = time.time()

        headers: dict[str, str] = payload.headers.model_dump() if payload.headers else {}

        # Extract namespace
        extract_start = time.time()
        URL = context.dict().get("global_context").get("metadata").get("tool").get("url")
        runtime = self.extract_nameSpace(str(URL))
        namespace = runtime.split("-")[0]
        extract_duration = (time.time() - extract_start) * 1000

        logger.error(f"[LATENCY] Namespace extraction | namespace={namespace}, duration={extract_duration:.2f}ms")

        # Get namespace record (with caching)
        namespace_start = time.time()
        record = await self.get_namespace_record(namespace)
        namespace_duration = (time.time() - namespace_start) * 1000

        if not record:
            total_duration = (time.time() - plugin_start_time) * 1000
            logger.warning(
                f"[LATENCY] No record found for namespace={namespace} | total={total_duration:.2f}ms"
            )
            return PluginResult(
                modified_payload=payload,
                continue_processing=True,
            )

        uid = record.get("uid")
        if not uid:
            total_duration = (time.time() - plugin_start_time) * 1000
            logger.warning(
                f"[LATENCY] No UID in record for namespace={namespace} | total={total_duration:.2f}ms"
            )
            return PluginResult(
                modified_payload=payload,
                continue_processing=True,
            )

        # Get bearer token (with caching)
        token_start = time.time()
        bearer_token = await self.get_bearer_token(uid)
        token_duration = (time.time() - token_start) * 1000

        # Set authorization header
        header_start = time.time()
        headers["Authorization"] = f"Bearer {bearer_token}"
        payload.headers = HttpHeaderPayload(root=headers)
        header_duration = (time.time() - header_start) * 1000

        total_duration = (time.time() - plugin_start_time) * 1000

        logger.error(
            f"[LATENCY] Auth header injection complete | "
            f"namespace={namespace}, uid={uid[:8]}... | "
            f"extract={extract_duration:.2f}ms, "
            f"namespace_lookup={namespace_duration:.2f}ms, "
            f"token_fetch={token_duration:.2f}ms, "
            f"header_set={header_duration:.2f}ms, "
            f"total={total_duration:.2f}ms"
        )

        return PluginResult(
            modified_payload=payload,
            continue_processing=True,
        )
