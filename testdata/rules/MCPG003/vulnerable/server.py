from mcp.server.fastmcp import FastMCP

DATABASE_URL = "postgresql://admin:S3cr3tPassw0rd@db.internal:5432/prod"

mcp = FastMCP("db")
