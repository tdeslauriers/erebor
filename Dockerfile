# build app
FROM golang:1.25 AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y make && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN make build

RUN go build -o main ./cmd

# run app
FROM ubuntu:22.04

WORKDIR /app

COPY --from=builder /app/main .

EXPOSE 8443

CMD ["./main"]