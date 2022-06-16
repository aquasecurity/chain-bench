FROM alpine as build

WORKDIR /home/chain-bench

RUN apk add --no-cache go make

COPY . .

RUN make build

FROM alpine as product

WORKDIR /home/chain-bench

COPY --from=build /home/chain-bench/chain-bench /usr/local/bin/chain-bench

ENTRYPOINT [ "chain-bench" ]
