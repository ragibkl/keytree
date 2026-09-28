# keytree as a container, for hosts where you'd rather not install anything.
# Host paths are mounted under /host and keytree runs with --root /host; see
# compose.example.yaml.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /keytree ./cmd/keytree

FROM alpine:3 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /keytree /keytree
ENTRYPOINT ["/keytree"]
CMD ["sync", "--root", "/host", "--every", "1h", "--jitter", "5m"]
