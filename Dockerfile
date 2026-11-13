FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /bridz .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /bridz /bridz
ENTRYPOINT ["/bridz"]
