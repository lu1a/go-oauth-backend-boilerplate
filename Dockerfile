FROM golang:1.21-alpine

WORKDIR /app
COPY . .

RUN go build -o backend main.go
RUN chmod +x backend

CMD ./backend
