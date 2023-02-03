FROM rust:latest AS builder

RUN rustup target add x86_64-unknown-linux-musl
RUN apt update && apt install -y musl-tools musl-dev
RUN update-ca-certificates

ENV USER=rs
ENV UID=10001

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"


WORKDIR /domain-recon-rs

COPY ./ .

RUN cargo build --target x86_64-unknown-linux-musl --release

RUN ls -lart

FROM debian:latest as dist

COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

WORKDIR /debpkgs

RUN mkdir -p domain-recon_1.0.0_amd64/DEBIAN && \
    mkdir -p domain-recon_1.0.0_amd64/usr/bin

COPY control domain-recon_1.0.0_amd64/DEBIAN

COPY --from=builder /domain-recon-rs/target/x86_64-unknown-linux-musl/release/domain-recon ./domain-recon_1.0.0_amd64/usr/bin/domain-recon

RUN dpkg-deb --build domain-recon_1.0.0_amd64

FROM scratch as artifact
COPY --from=dist /debpkgs/domain-recon_1.0.0_amd64.deb .

