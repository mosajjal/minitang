# Build stage: TinyGo for the smallest static binary.
FROM tinygo/tinygo:0.41.0 AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN tinygo build -opt=z -no-debug -o /minitang .

# socat for the listening socket; busybox for keygen utilities (openssl etc.
# are not bundled — generate keys on the host or via init container).
FROM alpine:3.20
RUN apk add --no-cache socat ca-certificates
COPY --from=build /minitang /usr/bin/minitang
COPY contrib/keygen.sh /usr/bin/minitang-keygen
RUN chmod +x /usr/bin/minitang-keygen

VOLUME ["/var/db/minitang"]
EXPOSE 8080

# Default: socat-driven listener, fork one minitang per connection.
ENTRYPOINT ["socat", "TCP-LISTEN:8080,fork,reuseaddr"]
CMD ["EXEC:/usr/bin/minitang /var/db/minitang"]
