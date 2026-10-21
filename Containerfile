FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/unifi-blocklist-chunker .
RUN mkdir -p /out/data

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/unifi-blocklist-chunker /unifi-blocklist-chunker
# Default exclusions volume mount point, owned by the runtime user so a
# fresh named volume inherits write access.
COPY --from=build --chown=65534:65534 /out/data /data
VOLUME ["/data"]
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/unifi-blocklist-chunker"]
