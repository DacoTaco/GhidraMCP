# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import json
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"
DEFAULT_REQUEST_TIMEOUT = 30

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER
# Initialize ghidra_request_timeout with default value
ghidra_request_timeout = DEFAULT_REQUEST_TIMEOUT

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=ghidra_request_timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str, params: dict = None) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, params=params, timeout=ghidra_request_timeout)
        else:
            response = requests.post(url, data=data.encode("utf-8"), params=params, timeout=ghidra_request_timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

def _with_program(params: dict, program: str) -> dict:
    """Attach the optional 'program' selector to a params dict when provided."""
    if program:
        params = dict(params)
        params["program"] = program
    return params

# Note on the `program` argument (present on every tool below):
# Ghidra can have several binaries open at once. Leave `program` empty ("") to
# act on the currently focused program (the original behavior). Pass a program
# name or project path (see list_open_programs) to target a specific binary,
# so multiple loaded binaries can be analyzed without switching tabs.

