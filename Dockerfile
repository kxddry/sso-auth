FROM golang:1.24 AS builder
LABEL authors="iv"

WORKDIR /app

COPY ./go.* ./
RUN go mod download

COPY ./ ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o app ./cmd/sso

FROM scratch
LABEL authors="iv"

COPY --from=builder /app/app /app/app

CMD ["/app/app"]
