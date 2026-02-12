FROM golang:1.26 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X 'main.version=${VERSION}'" -o /out/tcexecutor .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates proot && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /tmp/tcexecutor && chown -R 65532:65532 /tmp/tcexecutor
COPY --from=build /out/tcexecutor /tcexecutor
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/tcexecutor"]
