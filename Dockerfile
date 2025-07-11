FROM golang:1.24 AS builder
LABEL authors="iv"

WORKDIR /app

COPY ./go.* ./
RUN go mod download

COPY ./ ./

RUN go build -o app ./cmd/sso

FROM debian:bookworm-slim
LABEL authors="iv"

COPY --from=builder /app/app /app

COPY ${CONFIG_PATH} /

ENV CONFIG_PATH=/${CONFIG_PATH}
CMD ["/app"]