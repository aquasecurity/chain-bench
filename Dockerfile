FROM alpine:3.16 as build

WORKDIR /home/chain-bench

RUN apk add --no-cache go make

COPY . .

RUN make build

FROM alpine:3.16 as product

WORKDIR /home/chain-bench

RUN adduser -D -s /bin/sh -h /home/chain-bench user && \
    chown -R user:user /home/chain-bench

COPY --from=build /home/chain-bench/chain-bench /usr/local/bin/chain-bench

USER user

ENTRYPOINT [ "chain-bench" ]
