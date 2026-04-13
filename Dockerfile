FROM debian:bookworm-slim
ARG BINARY_PATH=target/release/sdl-service
RUN echo "Using binary: $BINARY_PATH"
COPY ${BINARY_PATH} /usr/local/bin/sdl-service
ENTRYPOINT ["sdl-service"]
CMD []
