# Multi-stage Dockerfile for Remote Executor MCP (mcp-execmesh)
# Target runtime memory footprint: < 15MB RSS

# Stage 1: Fast build using alpine or staged binary
# If pre-built binary exists in bin/remote-mcp, it can be copied directly
# Or build inside container using golang
FROM alpine:3.21

# Install runtime certificates, timezone data and wget for healthchecks
RUN apk add --no-cache ca-certificates tzdata wget \
    && addgroup -g 10001 -S mcpuser \
    && adduser -u 10001 -S -G mcpuser -h /var/lib/remote-mcp mcpuser \
    && mkdir -p /etc/remote-mcp /var/lib/remote-mcp /var/log/remote-mcp /etc/remote-mcp/secrets \
    && chown -R mcpuser:mcpuser /var/lib/remote-mcp /var/log/remote-mcp /etc/remote-mcp

# Copy statically compiled binary
COPY bin/remote-mcp /usr/local/bin/remote-mcp

# Switch to non-root user
USER 10001:10001
WORKDIR /var/lib/remote-mcp

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/remote-mcp"]
CMD ["-config", "/etc/remote-mcp/config.yaml"]




