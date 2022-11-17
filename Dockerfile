FROM rust:slim
RUN apt-get update && apt-get install pkg-config libssl-dev -y

WORKDIR /
RUN USER=root cargo new --bin rapi
WORKDIR /rapi

COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
RUN cargo check
RUN cargo build

RUN rm -rf src/*
COPY ./src ./src
RUN touch src/main.rs

RUN cargo build


CMD ["./target/debug/rapi"]
