from fastmcp import FastMCP

server = FastMCP("mcpenum-interop")


@server.tool
def heartbeat() -> str:
    """Return a fixed value for inventory tests."""
    return "ok"


if __name__ == "__main__":
    server.run(transport="http", host="127.0.0.1", port=14004, path="/api/v1/mcp")
