import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("weather")
NWS_API = "https://api.weather.gov"


@mcp.tool()
async def get_alerts(state: str) -> str:
    """Active weather alerts for a US state."""
    url = f"{NWS_API}/alerts/active/area/{state}"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers={"User-Agent": "weather/1.0"})
    return str(resp.status_code)
