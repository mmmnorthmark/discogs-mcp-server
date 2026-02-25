# Project Notes

- Public MCP tool registration applies `TOOL_NAME_PREFIX`, defaulting to `music`, so deployed tools are exposed as names like `music-search` while individual tool constants keep their unprefixed names for focused tests.
- The stream server binds to `SERVER_HOST`, defaulting to `0.0.0.0` so container and Cloud Run style deployments can accept external connections.
