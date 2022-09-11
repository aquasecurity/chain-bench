FROM alpine:3.16 as build

WORKDIR /home/chain-bench

RUN apk update && \
    apk --no-cache add make go

COPY . .

RUN make build

FROM alpine:3.16 as product

WORKDIR /home/chain-bench

COPY --from=build /home/chain-bench/chain-bench /usr/local/bin/chain-bench
COPY --from=build /home/chain-bench/templates/*.tpl templates/


ENTRYPOINT [ "chain-bench" ]