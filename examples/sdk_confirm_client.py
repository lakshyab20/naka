"""Official MCP SDK client that answers Naka's confirmation prompts.

Needs: pip install "mcp>=2". Run: python examples/sdk_confirm_client.py
"""
import asyncio
import os
import sys
from pathlib import Path

import mcp.types as types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = Path(__file__).resolve().parent
answers = iter([True, False])   # approve the first prompt, decline the second


async def on_elicit(context, params):
    allow = next(answers)
    print(f"  PROMPT SHOWN TO USER:\n    {params.message.replace(chr(10), chr(10) + '    ')}\n  user says: "
          f"{'allow' if allow else 'deny'}")
    return types.ElicitResult(action="accept", content={"allow": allow})


async def main():
    env = dict(os.environ)
    params = StdioServerParameters(command="naka", args=["wrap", "--name", "inbox", "--quiet", "--",
                                                             sys.executable, str(HERE / "sdk_confirm_server.py")],
                                   env=env)
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w, elicitation_callback=on_elicit) as s:
            await s.initialize()
            await s.list_tools()
            page = await s.call_tool("read_page", {"url": "https://recipes.example/pasta"})
            print("read_page ->", page.content[0].text[:60], "...")
            for attempt in (1, 2):
                res = await s.call_tool("send_email", {"to": "amy.watson@gmail.com", "body": "addresses"})
                print(f"send_email attempt {attempt} -> error={res.isError if hasattr(res, 'isError') else res.is_error} | "
                      f"{res.content[0].text[:90]}")

asyncio.run(main())
