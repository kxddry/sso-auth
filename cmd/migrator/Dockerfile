FROM golang:1.24 AS builder
LABEL authors="iv"

WORKDIR /app

COPY ./go.* ./
RUN go mod download

COPY ./ ./

RUN go build -o app ./cmd/migrator

FROM debian:bookworm-slim
LABEL authors="iv"

COPY --from=builder /app/app /app

COPY ${MIGRATION_CONFIG_PATH} /

ENV CONFIG_PATH=/${MIGRATION_CONFIG_PATH}

CMD ["/app"]
