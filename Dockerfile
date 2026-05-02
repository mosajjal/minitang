# Build stage: stdgo for portable cross-arch builds. Produces a static
# CGO-disabled binary that works on alpine without glibc.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /src/minitang .

FROM alpine:3.20
RUN apk add --no-cache socat ca-certificates
COPY --from=build /src/minitang /usr/bin/minitang
COPY contrib/keygen.sh /usr/bin/minitang-keygen
RUN chmod +x /usr/bin/minitang-keygen

VOLUME ["/var/db/minitang"]
EXPOSE 8080

# Default: socat-driven listener, fork one minitang per connection.
ENTRYPOINT ["socat", "TCP-LISTEN:8080,fork,reuseaddr"]
CMD ["EXEC:/usr/bin/minitang /var/db/minitang"]
