"""Official SDK client (stdio) -> tripline -> remote server (Streamable HTTP).

Run the server first: python examples/sdk_http_server.py 8765
Then: python examples/sdk_http_client.py http://127.0.0.1:8765/mcp
"""
import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main(url):
    params = StdioServerParameters(command="tripline", args=["wrap", "--name", "remote-notes", "--quiet",
                                                             "--url", url, "--header", "X-Demo: 1"])
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            init = await s.initialize()
            print("initialized with", init.serverInfo.name if hasattr(init, "serverInfo") else init.server_info.name)
            print("tools:", [t.name for t in (await s.list_tools()).tools])
            for name, args in [("add", {"a": 2, "b": 3}), ("read_note", {"name": "todo"}),
                               ("read_note", {"name": "scraped"})]:
                res = await s.call_tool(name, args)
                err = res.isError if hasattr(res, "isError") else res.is_error
                print(f"{name}{args} -> error={err} | {res.content[0].text[:90]}")

asyncio.run(main(sys.argv[1]))
