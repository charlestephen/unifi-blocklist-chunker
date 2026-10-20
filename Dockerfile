FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/unifi-blocklist-chunker .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/unifi-blocklist-chunker /unifi-blocklist-chunker
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/unifi-blocklist-chunker"]
