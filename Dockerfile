# Runtime image for mcp-guard. Built by GoReleaser (dockers_v2), which places the
# prebuilt binary for each platform at $TARGETPLATFORM/mcp-guard in the build context.
FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/mcp-guard /usr/local/bin/mcp-guard

# Mount the project to scan at /src:
#   docker run --rm -v "$PWD:/src" ghcr.io/gerijacki/mcp-guard
WORKDIR /src
ENTRYPOINT ["/usr/local/bin/mcp-guard"]
CMD ["scan", "."]
