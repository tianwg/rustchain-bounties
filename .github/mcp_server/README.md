# RustChain MCP Server

> Connects **any MCP-compatible AI agent** (Claude Code, Cursor, Windsurf, VS Code Copilot) to RustChain in one command.

## Install

```bash
# One-liner (uvx — no install needed)
uvx rustchain-mcp

# Or install via pip
pip install rustchain-mcp
rustchain-mcp
```

## Claude Code Setup

Add to your `~/.claude/settings.local.json` or project `.mcp.json`:

```json
{
  "mcpServers": {
    "rustchain": {
      "command": "uvx",
      "args": ["rustchain-mcp"]
    }
  }
}
```

Or for pip-installed version:

```json
{
  "mcpServers": {
    "rustchain": {
      "command": "rustchain-mcp"
    }
  }
}
```

Then restart Claude Code. The RustChain tools are available immediately.

## Available Tools

| Tool | Description |
|------|-------------|
| `rustchain_health` | Check node health and connectivity |
| `rustchain_balance` | Query RTC wallet balance by miner_id |
| `rustchain_miners` | List active miners on the network |
| `rustchain_epoch` | Get current epoch information |
| `rustchain_create_wallet` | Register a new agent wallet |
| `rustchain_submit_attestation` | Submit hardware fingerprint (PoP) |
| `rustchain_bounties` | List open bounties on RustChain |
| `rustchain_transfer` | Transfer RTC between wallets |

## Examples

### Check your wallet balance

```
rustchain_balance(miner_id="founder_community")
```

### Create a wallet for your agent

```
rustchain_create_wallet(wallet_name="my-agent-001")
```

### List open bounties

```
rustchain_bounties(status="open", limit=10)
```

### Submit hardware attestation

```
rustchain_submit_attestation(
    miner_id="my-agent-001",
    hardware_signature="sig_from_node_attestation"
)
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUSTCHAIN_NODE_URL` | `https://50.28.86.131` | RustChain node endpoint |

## Cursor / Windsurf Setup

Add to Cursor settings (`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "rustchain": {
      "command": "uvx",
      "args": ["rustchain-mcp"]
    }
  }
}
```

## How It Works

The server implements the **Model Context Protocol** over stdio. When Claude Code (or any MCP client) starts, it spawns the server process and communicates via JSON-RPC 2.0 over stdin/stdout.

The server translates MCP tool calls into RustChain REST API calls and returns formatted JSON responses.

## Development

```bash
git clone https://github.com/Scottcjn/rustchain-mcp
cd rustchain-mcp
pip install -e ".[cli]"
rustchain-mcp
```

## License

MIT
