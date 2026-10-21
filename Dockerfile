# ndes sync server with its web GUI.
#   docker build -t ndesd .
#   docker run -d --name ndesd -v ndesd-data:/data -p 127.0.0.1:8080:8080 -p 8485:8485 ndesd
# Then open http://127.0.0.1:8080 and follow the setup code from `docker logs ndesd`.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /ndesd ./cmd/ndesd && mkdir -p /out/data

# Starts as root only to fix /data ownership, then ndesd switches to 65532
# (NDESD_RUN_AS) before serving anything.
FROM gcr.io/distroless/static-debian12
COPY --from=build /ndesd /ndesd
COPY --from=build --chown=65532:65532 /out/ /
ENV NDESD_RUN_AS=65532:65532 NDESD_DATA=/data NDESD_ADMIN_LISTEN=0.0.0.0:8080 NDESD_SYNC_LISTEN=0.0.0.0:8485
VOLUME /data
EXPOSE 8080 8485
ENTRYPOINT ["/ndesd"]
