FROM docker.io/library/golang:1.16 AS builder

RUN mkdir /workspace/
COPY main.go go.mod /workspace/
WORKDIR /workspace/
ENV CGO_ENABLED=0
RUN go build -o serve-socket

FROM docker.io/library/alpine:3.13.6

RUN apk --update add --no-cache openssh bash shadow && rm -rf /var/cache/apk/*

COPY etc/ssh /etc/ssh
RUN chmod og-rwx /etc/ssh/*_key
COPY entrypoint.sh /usr/local/bin

RUN addgroup testuser && adduser testuser -G testuser -D
RUN echo "root:iddqd" | chpasswd
RUN echo "testuser:idkfa" | chpasswd

RUN su testuser && mkdir /home/testuser/.ssh/
COPY --chown=testuser:testuser id_ed25519.pub id_rsa.pub /tmp/
RUN cat /tmp/id_ed25519.pub /tmp/id_rsa.pub >> /home/testuser/.ssh/authorized_keys

COPY --from=builder /workspace/serve-socket /usr/local/bin

EXPOSE 22
EXPOSE 2222

CMD ["entrypoint.sh"]
