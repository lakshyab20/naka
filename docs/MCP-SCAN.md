# The MCP server scan

We started the most downloaded MCP servers and read what they tell an AI about themselves. **None of the 75 servers that started hid instructions for the AI. But 12 of them give a single injected message everything it needs to steal data on its own, including the official GitHub, Slack and Notion servers.**

Scanned on 5 November 2026 with `naka audit` (119 servers tried: the 100 most downloaded MCP servers on npm, plus 19 popular Python servers; 75 started and listed their tools). Raw results: [`scan/2026-11-05.json`](scan/2026-11-05.json). The scan reruns every Monday in [GitHub Actions](../.github/workflows/mcp-scan.yml), on a throwaway machine with placeholder settings only.

## What we looked for

| Finding | Servers | What it means |
|---|---:|---|
| Hidden instructions for the AI (tool poisoning) | 0 / 75 | One false alarm, reviewed below |
| Outside content + private data + a way out ("lethal trifecta") | 12 / 75 | One injected message in what the server reads can make the AI read your private data and send it out, with no other server involved |
| Outside content + runs code | 8 / 75 | An injected page or issue can lead straight to code running in your browser or system |
| Tool safety labels (MCP annotations) declared | 43 / 75 | Apps use these to tell readers from tools that change or delete things |

None of these are bugs in the servers. Reading issues and posting comments is what a GitHub server is for. The point is where a firewall has to sit: with a lethal-trifecta server installed, prompt injection doesn't need a second server to do damage.

## One message is enough: the lethal trifecta

Simon Willison named the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/): an agent that reads untrusted content, can reach private data and can send data out can be made to leak that data by anyone who can write to what it reads. These servers have all three in one install:

| Server | Weekly downloads | Reads outside content | Reads private data | Sends data out |
|---|---:|---|---|---|
| `@notionhq/notion-mcp-server` | 387,210 | `API-retrieve-a-comment` | `API-get-user`, `API-get-users` | `API-post-page`, `API-retrieve-a-comment` |
| `@modelcontextprotocol/server-github` | 189,189 | `list_issues`, `search_issues` | `get_file_contents`, `fork_repository` | `create_issue`, `create_pull_request` |
| `@modelcontextprotocol/server-slack` | 185,396 | `slack_get_channel_history`, `slack_get_thread_replies` | `slack_get_channel_history`, `slack_get_users` | `slack_post_message`, `slack_reply_to_thread` |
| `@zencoderai/slack-mcp-server` | 64,576 | `slack_get_channel_history`, `slack_get_thread_replies` | `slack_get_channel_history`, `slack_get_users` | `slack_post_message`, `slack_reply_to_thread` |
| `@apify/actors-mcp-server` | 31,362 | `search-actors`, `fetch-actor-details` | `get-key-value-store-record` | `fetch-actor-details`, `fetch-actor-mcp-tool-list` |
| `@angelogiacco/elevenlabs-mcp-server` | 28,234 | `Simulates_A_Conversation`, `Simulates_A_Conversation_Stream_` | `Get_History_Item`, `Get_Audio_From_History_Item` | `Invite_User`, `Invite_Multiple_Users` |
| `@executeautomation/playwright-mcp-server` | 13,447 | `get_codegen_session`, `playwright_navigate` | `playwright_console_logs`, `playwright_custom_user_agent` | `playwright_navigate`, `playwright_upload_file` |
| `@thirdstrandstudio/mcp-figma` | 11,389 | `figma_get_comments`, `figma_get_comment_reactions` | `figma_get_file`, `figma_get_file_nodes` | `figma_post_comment`, `figma_delete_comment` |
| `@agentdeskai/browser-tools-mcp` | 5,548 | `listBrowserTabs`, `getConsoleLogs` | `getConsoleLogs`, `getNetworkLogs` | `listBrowserTabs`, `refreshBrowser` |
| `@sigmacomputing/slack-mcp-server` | 4,256 | `slack_get_channel_history`, `slack_get_thread_replies` | `slack_get_channel_history`, `slack_get_users` | `slack_post_message`, `slack_reply_to_thread` |
| `@transcend-io/mcp` | 4,217 | `consent_cookie_triage_review_app`, `assessments_list_comments` | `consent_list_roc_records`, `inventory_list_business_entities` | `dsr_submit`, `assessments_write_comment` |
| `mcp-atlassian` | PyPI | `jira_get_issue_watchers`, `jira_get_issue` | `jira_get_user_profile`, `jira_search_assignable_users` | `jira_create_issue`, `jira_add_comment` |

The GitHub row is the pattern behind [Invariant Labs' 2025 GitHub MCP exploit](https://invariantlabs.ai/blog/mcp-github-vulnerability): a public issue tells the agent to read a private repository and post what it finds in a pull request.

## From a web page to running code

| Server | Weekly downloads | Reads outside content | Runs code |
|---|---:|---|---|
| `@playwright/mcp` | 10,188,231 | `browser_console_messages`, `browser_handle_dialog` | `browser_evaluate`, `browser_run_code_unsafe` |
| `chrome-devtools-mcp` | 1,876,272 | `get_console_message`, `list_console_messages` | `evaluate_script` |
| `@sentry/mcp-server` | 237,679 | `analyze_issue_with_seer`, `search_issues` | `execute_sentry_tool` |
| `next-devtools-mcp` | 159,006 | `browser_eval` | `browser_eval` |
| `@modelcontextprotocol/server-puppeteer` | 29,827 | `puppeteer_navigate` | `puppeteer_evaluate` |
| `@executeautomation/playwright-mcp-server` | 13,447 | `get_codegen_session`, `playwright_navigate` | `playwright_evaluate` |
| `@wdio/mcp` | 8,119 | `navigate` | `execute_script` |
| `puppeteer-mcp-server` | 5,093 | `puppeteer_navigate` | `puppeteer_evaluate` |

Most of these run JavaScript in a browser the agent controls, which may be signed in to your accounts. Sentry's `execute_sentry_tool` runs Sentry's own actions, and Sentry issues are written by whoever can send your app an error, the route behind the 2026 [agentjacking](https://labs.cloudsecurityalliance.org/research/csa-research-note-agentjacking-mcp-sentry-injection-20260612/) reports.

## The one false alarm

`next-devtools-mcp` (Vercel's Next.js server) was flagged for hidden instructions: a tool description contains `[IMPORTANT] If auto-discovery returns no servers: ...`. Reading it, this is ordinary guidance for the AI, written in the same style attackers use. It shows why a scanner that only matches patterns can't be the whole defence: legitimate servers talk to the AI the same way poisoned ones do.

## Tool lists eat context

Every tool definition is sent to the AI before it does anything. The median server used about 3,772 tokens; these used far more:

| Server | Tools | Tokens of context |
|---|---:|---:|
| `@angelogiacco/elevenlabs-mcp-server` | 513 | 87,730 |
| `@lottiefiles/creator-mcp` | 108 | 74,116 |
| `@togglhq/mcp` | 55 | 33,439 |
| `mcp-atlassian` | 98 | 30,117 |
| `@clipform/mcp-server` | 32 | 26,462 |
| `@transcend-io/mcp` | 91 | 26,327 |
| `firecrawl-mcp` | 28 | 25,475 |
| `mongodb-mcp-server` | 31 | 20,966 |

## Every server that started

Capabilities are read from tool names as verb + object (`get_issue` reads outside content, `read_file` reads private data, `create_issue` sends data out), so treat them as a guide and check the tools listed. Weekly downloads are from npm at the time of the scan.

| # | Server | Weekly downloads | Tools | Context (tokens) | Annotated | Findings |
|---:|---|---:|---:|---:|---:|---|
| 1 | `@playwright/mcp` | 10,188,231 | 25 | 5,517 | 25/25 | injection-to-command |
| 3 | `chrome-devtools-mcp` | 1,876,272 | 32 | 7,758 | 32/32 | injection-to-command |
| 4 | `@modelcontextprotocol/server-filesystem` | 1,294,151 | 14 | 3,443 | 14/14 | none |
| 5 | `@upstash/context7-mcp` | 741,246 | 2 | 1,321 | 2/2 | none |
| 6 | `@wonderwhy-er/desktop-commander` | 724,305 | 25 | 13,538 | 25/25 | none |
| 7 | `@notionhq/notion-mcp-server` | 387,210 | 24 | 20,473 | 24/24 | lethal-trifecta |
| 8 | `@modelcontextprotocol/server-everything` | 315,517 | 13 | 2,024 | 13/13 | none |
| 9 | `@modelcontextprotocol/server-memory` | 297,809 | 9 | 2,952 | 9/9 | none |
| 10 | `@sentry/mcp-server` | 237,679 | 9 | 6,763 | 9/9 | injection-to-command |
| 12 | `@supabase/mcp-server-supabase` | 205,830 | 31 | 6,275 | 31/31 | none |
| 13 | `@modelcontextprotocol/server-github` | 189,189 | 26 | 4,229 | 0/26 | lethal-trifecta |
| 14 | `mongodb-mcp-server` | 186,455 | 31 | 20,966 | 31/31 | none |
| 15 | `@modelcontextprotocol/server-slack` | 185,396 | 8 | 818 | 0/8 | lethal-trifecta |
| 16 | `@modelcontextprotocol/server-sequential-thinking` | 183,170 | 1 | 1,191 | 1/1 | none |
| 19 | `next-devtools-mcp` | 159,006 | 4 | 1,435 | 0/4 | hidden-instructions, injection-to-command |
| 21 | `@modelcontextprotocol/server-postgres` | 155,598 | 1 | 34 | 0/1 | none |
| 22 | `firecrawl-mcp` | 147,462 | 28 | 25,475 | 28/28 | none |
| 24 | `@sap-ux/fiori-mcp-server` | 128,468 | 9 | 8,113 | 9/9 | none |
| 25 | `@shopify/dev-mcp` | 80,037 | 5 | 6,733 | 0/5 | none |
| 26 | `exa-mcp-server` | 76,410 | 3 | 1,735 | 3/3 | none |
| 27 | `@cap-js/mcp-server` | 75,069 | 2 | 584 | 2/2 | none |
| 28 | `scryfall-mcp-server` | 73,446 | 7 | 581 | 0/7 | none |
| 29 | `@zencoderai/slack-mcp-server` | 64,576 | 8 | 1,075 | 0/8 | lethal-trifecta |
| 30 | `@browsermcp/mcp` | 59,872 | 1 | 292 | 1/1 | none |
| 31 | `@netlify/mcp` | 54,818 | 10 | 5,746 | 10/10 | none |
| 32 | `@statelyai/mcp` | 47,695 | 20 | 16,122 | 20/20 | none |
| 33 | `@hubspot/mcp-server` | 45,299 | 21 | 10,407 | 21/21 | none |
| 35 | `@metamask/device-mcp` | 42,796 | 29 | 4,625 | 10/29 | none |
| 37 | `@apify/actors-mcp-server` | 31,362 | 12 | 14,256 | 12/12 | lethal-trifecta |
| 38 | `@modelcontextprotocol/server-brave-search` | 30,371 | 2 | 374 | 0/2 | none |
| 39 | `@modelcontextprotocol/server-puppeteer` | 29,827 | 7 | 645 | 0/7 | injection-to-command |
| 40 | `mcp-server-kubernetes` | 29,714 | 23 | 6,293 | 22/23 | none |
| 42 | `@angelogiacco/elevenlabs-mcp-server` | 28,234 | 513 | 87,730 | 0/513 | lethal-trifecta |
| 43 | `wikipedia-mcp` | 25,645 | 2 | 149 | 0/2 | none |
| 44 | `tavily-mcp` | 24,480 | 5 | 2,018 | 0/5 | none |
| 46 | `@mui/mcp` | 23,962 | 2 | 808 | 0/2 | none |
| 47 | `@productbrain/mcp` | 23,856 | 16 | 16,938 | 16/16 | none |
| 48 | `@circleci/mcp-server-circleci` | 23,271 | 13 | 13,077 | 5/13 | none |
| 49 | `@togglhq/mcp` | 22,203 | 55 | 33,439 | 55/55 | none |
| 58 | `appium-mcp` | 16,850 | 32 | 11,226 | 32/32 | none |
| 62 | `@executeautomation/playwright-mcp-server` | 13,447 | 33 | 3,650 | 0/33 | lethal-trifecta, injection-to-command |
| 64 | `@primer/mcp` | 11,688 | 20 | 2,023 | 20/20 | none |
| 65 | `@thirdstrandstudio/mcp-figma` | 11,389 | 31 | 4,166 | 0/31 | lethal-trifecta |
| 66 | `sample-aws-pricing-calculator-mcp` | 11,302 | 10 | 5,636 | 10/10 | none |
| 68 | `@magicuidesign/mcp` | 10,905 | 3 | 683 | 3/3 | none |
| 70 | `chelaile-mcp-server` | 9,643 | 15 | 8,525 | 15/15 | none |
| 71 | `@heroku/mcp-server` | 8,575 | 33 | 5,615 | 0/33 | none |
| 72 | `@wdio/mcp` | 8,119 | 17 | 4,784 | 17/17 | injection-to-command |
| 73 | `@modelcontextprotocol/server-google-maps` | 7,846 | 7 | 701 | 0/7 | none |
| 74 | `@rsdoctor/mcp-server` | 7,615 | 15 | 2,736 | 0/15 | none |
| 77 | `@react-aria/mcp` | 7,150 | 3 | 343 | 3/3 | none |
| 78 | `@phantom/mcp-server` | 6,720 | 30 | 12,737 | 30/30 | none |
| 81 | `@agentdeskai/browser-tools-mcp` | 5,548 | 16 | 7,036 | 16/16 | lethal-trifecta |
| 83 | `puppeteer-mcp-server` | 5,093 | 8 | 613 | 0/8 | injection-to-command |
| 85 | `@negokaz/excel-mcp-server` | 4,768 | 6 | 1,505 | 6/6 | none |
| 86 | `@coinbase/cds-mcp-server` | 4,675 | 2 | 237 | 0/2 | none |
| 87 | `@infineon/design-system-mcp` | 4,514 | 4 | 834 | 0/4 | none |
| 90 | `@sigmacomputing/slack-mcp-server` | 4,256 | 17 | 2,424 | 0/17 | lethal-trifecta |
| 92 | `@transcend-io/mcp` | 4,217 | 91 | 26,327 | 91/91 | lethal-trifecta |
| 94 | `@lottiefiles/creator-mcp` | 3,967 | 108 | 74,116 | 0/108 | none |
| 97 | `langsmith-mcp-server` | 3,707 | 15 | 3,772 | 0/15 | none |
| 98 | `@clipform/mcp-server` | 3,648 | 32 | 26,462 | 32/32 | none |
|  | `arxiv-mcp-server` | PyPI | 19 | 4,618 | 19/19 | none |
|  | `awslabs.aws-documentation-mcp-server` | PyPI | 5 | 5,784 | 0/5 | none |
|  | `blender-mcp` | PyPI | 9 | 4,328 | 0/9 | none |
|  | `duckduckgo-mcp-server` | PyPI | 3 | 1,175 | 0/3 | none |
|  | `markitdown-mcp` | PyPI | 1 | 112 | 0/1 | none |
|  | `mcp-atlassian` | PyPI | 98 | 30,117 | 98/98 | lethal-trifecta, mentions-other-tools |
|  | `mcp-obsidian` | PyPI | 15 | 2,367 | 0/15 | none |
|  | `mcp-server-calculator` | PyPI | 1 | 100 | 0/1 | none |
|  | `mcp-server-docker` | PyPI | 19 | 4,596 | 19/19 | none |
|  | `mcp-server-fetch` | PyPI | 1 | 381 | 1/1 | none |
|  | `mcp-server-qdrant` | PyPI | 2 | 225 | 0/2 | none |
|  | `mcp-server-time` | PyPI | 3 | 1,146 | 3/3 | none |
|  | `zotero-mcp` | PyPI | 3 | 993 | 0/3 | none |

## Didn't start (44)

Most need a real account, a running database or a cloud login before they'll list their tools, and the scan only uses placeholder settings. These aren't findings: `@modelcontextprotocol/server-pdf`, `@pandacss/mcp`, `@azure/mcp`, `figma-developer-mcp`, `agentation-mcp`, `@azure-devops/mcp`, `@winor30/mcp-server-datadog`, `replicate-mcp`, `vercel-mcp`, `axe-mcp-server`, `@aventurevc/mcp-server`, `@benborla29/mcp-server-mysql`, `backlog-mcp-server`, `@stripe/mcp`, `@contentful/mcp-server`, `@socketsecurity/mcp`, `@gongrzhe/server-gmail-autoauth-mcp`, `@auth0/auth0-mcp-server`, `tiny-http-mcp-server`, `@xeroapi/xero-mcp-server`, `@21st-dev/magic`, `@sap/mdk-mcp-server`, `@fanyangmeng/ghost-mcp`, `@ivotoby/openapi-mcp-server`, `@transcend-io/mcp-server-consent`, `@transcend-io/mcp-server-inventory`, `@air/mcp`, `@modelcontextprotocol/server-gdrive`, `@amap/amap-maps-mcp-server`, `@penpot/mcp`, `@transcend-io/mcp-server-admin`, `@transcend-io/mcp-server-dsr`, `@transcend-io/mcp-server-discovery`, `@transcend-io/mcp-server-assessment`, `@elastic/mcp-server-elasticsearch`, `@cloudflare/mcp-server-cloudflare`, `twelvelabs-mcp`, `@transcend-io/mcp-server-workflows`, `mcp-server-git`, `mcp-server-sqlite`, `awslabs.core-mcp-server`, `mcp-youtube-transcript`, `mcp-server-motherduck`, `serper-mcp-server`.

## Check a server yourself

```bash
pip install naka
naka audit -- npx -y @modelcontextprotocol/server-github
```

`naka audit` only reads a server's lists and never calls a tool, but it does start the server, which runs its code. Run unknown servers somewhere disposable (a container, a VM, or a GitHub Actions job like ours). To stop the attacks, not just spot the risk, put the server behind Naka: `naka install`.
