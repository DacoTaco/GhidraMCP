

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse/streamable-http), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse/streamable-http), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse", "streamable-http", "streamable_http"],
                        help="Transport protocol for MCP, default: stdio (sse is deprecated; use streamable-http)")
    parser.add_argument("--ghidra-timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                        help=f"MCP requests timeout, default: {DEFAULT_REQUEST_TIMEOUT}")
    args = parser.parse_args()

    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
        
    global ghidra_request_timeout
    if args.ghidra_timeout:
        ghidra_request_timeout = args.ghidra_timeout
    
    transport = args.transport.replace("_", "-")
    if transport in ("sse", "streamable-http"):
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            if transport == "sse":
                logger.warning("SSE transport is deprecated in MCP; prefer streamable-http.")
                logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}{mcp.settings.sse_path}")
            else:
                logger.info(
                    "Starting MCP server on http://%s:%s%s",
                    mcp.settings.host,
                    mcp.settings.port,
                    mcp.settings.streamable_http_path,
                )
            logger.info(f"Using transport: {transport}")

            mcp.run(transport=transport)
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()

if __name__ == "__main__":
    main()
