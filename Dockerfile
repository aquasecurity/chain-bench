FROM alpine:3.16 as build

WORKDIR /home/chain-bench

RUN apk update && \
    apk --no-cache --rm add make

COPY . .

ENV CGO_ENABLED=0
RUN make build

FROM alpine:3.16 as product

RUN addgroup -S chainbench && adduser -S chainbench -G chainbench

WORKDIR /home/chain-bench

COPY --from=build /home/chain-bench/chain-bench /usr/local/bin/chain-bench
COPY --from=build /home/chain-bench/templates/*.tpl templates/

USER chainbench

ENTRYPOINT [ "chain-bench" ]