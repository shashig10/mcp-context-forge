import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import httpx
import os
import orjson



class SigV4MCPAuth(httpx.Auth):
    """AWS SigV4 Auth handler for Bedrock AgentCore MCP endpoints."""


    def __init__(self, region: str = None):
        self.session = boto3.Session()
        self.region = region or os.getenv("AWS_REGION", "eu-central-1")

    def auth_flow(self, request: httpx.Request):
        creds = self.session.get_credentials().get_frozen_credentials()
        payload = orjson.loads(request.content.decode()) if request.content else {}
        if "method" in payload and (payload["method"] == "initialize" or payload["method"] == "message/send") :
            filtered = {
                "host": request.url.host,
                "content-type": request.headers.get("content-type", ""),
                "accept": request.headers.get("accept", "")
            }
        elif "jsonrpc" not in payload:
            filtered = {
                "host": request.url.host,
                "content-type": request.headers.get("content-type", ""),
                "accept": request.headers.get("accept", "")
            }
        else:
            filtered = {
                "host": request.url.host,
                "content-type": request.headers.get("content-type", ""),
                "accept": request.headers.get("accept", ""),
                "mcp-session-id": request.headers.get("mcp-session-id", ""),
            }
        aws_req = AWSRequest(
            method=request.method,
            url=str(request.url),
            headers=filtered,
            data=request.content,
        )
        SigV4Auth(creds, "bedrock-agentcore", self.region).add_auth(aws_req)

        for k, v in aws_req.headers.items():
            request.headers[k] = v

        yield request
