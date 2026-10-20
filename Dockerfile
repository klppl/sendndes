# Valv sync server with its web GUI.
#   docker build -t valvd .
#   docker run -d --name valvd -v valvd-data:/data -p 127.0.0.1:8080:8080 -p 8485:8485 valvd
# Then open http://127.0.0.1:8080 and follow the setup code from `docker logs valvd`.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /valvd ./cmd/valvd && mkdir -p /out/data

# Starts as root only to fix /data ownership, then valvd switches to 65532
# (VALVD_RUN_AS) before serving anything.
FROM gcr.io/distroless/static-debian12
COPY --from=build /valvd /valvd
COPY --from=build --chown=65532:65532 /out/ /
ENV VALVD_RUN_AS=65532:65532 VALVD_DATA=/data VALVD_ADMIN_LISTEN=0.0.0.0:8080 VALVD_SYNC_LISTEN=0.0.0.0:8485
VOLUME /data
EXPOSE 8080 8485
ENTRYPOINT ["/valvd"]
