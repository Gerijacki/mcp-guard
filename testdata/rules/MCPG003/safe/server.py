import os

from mcp.server.fastmcp import FastMCP

API_KEY = os.environ["SEARCH_API_KEY"]
token_type = "access_token"
max_tokens = 1000
password_field = "password"
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://localhost:5432/dev")

mcp = FastMCP("search")
