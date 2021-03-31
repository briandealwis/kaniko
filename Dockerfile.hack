# Install Qemu
FROM debian:buster AS qemu
RUN apt-get update && apt-get install -y qemu-user-static

FROM golang:1.16 as kaniko
WORKDIR /k
COPY . .
RUN go build -ldflags '-extldflags "-static" -w -s' -o /executor ./cmd/executor

FROM gcr.io/kaniko-project/executor:latest
COPY --from=qemu /usr/bin/qemu-x86_64-static /kaniko/qemu-amd64
COPY --from=qemu /usr/bin/qemu-aarch64-static /kaniko/qemu-arm64
COPY --from=qemu /usr/bin/qemu-arm-static /kaniko/qemu-arm
COPY --from=kaniko /executor /kaniko/executor
