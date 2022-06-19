FROM alpine:3.16 
RUN apk --no-cache add ca-certificates
COPY chain-bench /usr/local/bin/chain-bench
ENTRYPOINT [ "chain-bench" ]
