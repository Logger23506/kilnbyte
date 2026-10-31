FROM rust:1 AS build
WORKDIR /src
COPY . .
RUN cargo build --release

FROM debian:stable-slim
COPY --from=build /src/target/release/kilnbyte /usr/local/bin/kilnbyte
WORKDIR /data
ENV KBY_DATA=/data/chain.dat
EXPOSE 8899
# Pass the reward address and peers as arguments, e.g.:
#   docker run -p 8899:8899 -v kby:/data kilnbyte --miner <ADDR> --peer <seed>:8899
ENTRYPOINT ["kilnbyte", "node", "--public"]
