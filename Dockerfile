FROM rust:slim
RUN apt-get update && apt-get install pkg-config libssl-dev -y

ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL sparse

WORKDIR /
RUN USER=root cargo new --bin rapi
WORKDIR /rapi

COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
RUN cargo build

RUN rm -rf src/*
COPY ./src ./src
RUN touch src/main.rs
RUN cargo test
RUN cargo build


CMD ["./target/debug/rapi"]
