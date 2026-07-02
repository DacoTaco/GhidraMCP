[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/releases)
[![GitHub stars](https://img.shields.io/github/stars/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/graphs/contributors)
[![Follow @lauriewired](https://img.shields.io/twitter/follow/lauriewired?style=social)](https://twitter.com/lauriewired)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)


# ghidraMCP
ghidraMCP is an Model Context Protocol server for allowing LLMs to autonomously reverse engineer applications. It exposes numerous tools from core Ghidra functionality to MCP clients.

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9


# Features
MCP Server + Ghidra Plugin

- Decompile and analyze binaries in Ghidra
- Automatically rename methods and data
- List methods, classes, imports, and exports

# Installation

## Prerequisites
- Install [Ghidra](https://ghidra-sre.org)
- Python3 (only required for the optional Python compatibility wrapper)
- MCP [SDK](https://github.com/modelcontextprotocol/python-sdk) if you plan to use `bridge_mcp_ghidra.py`

## Ghidra
First, download the latest [release](https://github.com/DacoTaco/GhidraMCP/releases) from this repository. This release contains the Ghidra plugin. Then, import the plugin into Ghidra.

1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `GhidraMCP-1-2.zip` (or your chosen version) from the downloaded release
5. Restart Ghidra
6. Make sure the GhidraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`
7. *Optional*: Configure the port in Ghidra with `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server`
8. The embedded MCP endpoint defaults to `http://127.0.0.1:8080/mcp`.

Video Installation Guide:


https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3



## MCP Clients

The GhidraMCP plugin now includes an embedded MCP server inside Ghidra. The default MCP endpoint is:

- `http://127.0.0.1:8080/mcp`

Most clients can use this URL directly. The Python script `bridge_mcp_ghidra.py` is now optional and is only required for compatibility with clients that need a local command wrapper or stdio transport.

## Example 1: Claude Desktop
If Claude Desktop requires a local command wrapper, use the Python bridge in stdio mode:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
        "--transport",
        "stdio",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

If your client supports native HTTP, connect directly to:

- `http://127.0.0.1:8080/mcp`

## Example 2: Cline
For direct MCP support, configure Cline to use the embedded plugin endpoint:

1. Server Name: GhidraMCP
2. Server URL: `http://127.0.0.1:8080/mcp`

If you need the Python compatibility wrapper instead, run:

```
python bridge_mcp_ghidra.py --transport streamable-http --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

Then point Cline to the wrapper's generated HTTP endpoint shown in the bridge log.

## Example 3: 5ire
If 5ire requires a command wrapper, use the compatibility bridge:

1. Tool Key: ghidra
2. Name: GhidraMCP
3. Command: `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py --transport stdio --ghidra-server http://127.0.0.1:8080/`

If 5ire supports HTTP MCP directly, use:

- `http://127.0.0.1:8080/mcp`

# Building from Source

To build from source, you need to set the `GHIDRA_INSTALL_DIR` environment variable to point to your Ghidra installation directory. This can be done as follows:
- Windows: Running set GHIDRA_INSTALL_DIR=`<Absolute path to Ghidra without quotations>`
- macos/Linux: Running export GHIDRA_INSTALL_DIR=`<Absolute path to Ghidra>`

Build with Gradle by simply running:

`gradle`

The generated zip file includes the built Ghidra plugin and its resources. These files are required for Ghidra to recognize the new extension.