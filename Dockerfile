FROM rust:latest as build
RUN USER=root cargo new auth
WORKDIR /auth
RUN echo $(pwd)
RUN echo $(ls)
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
RUN cargo build --release
RUN rm src/*.rs
COPY ./src ./src
RUN rm ./target/release/auth*
RUN cargo build --release

FROM rust:latest
COPY --from=build /auth/target/release/auth .
CMD ["./auth"]
