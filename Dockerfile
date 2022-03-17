FROM harbor.stingray-tooling.com/docker.io-library/golang:1.17-alpine as build_modules

ENV GOPROXY=https://athens.stingray-tooling.com

WORKDIR /src
COPY go.mod /src
COPY go.sum /src

RUN go mod download

FROM build_modules AS build

COPY . /src

ENV GOOS=linux
ENV GOARCH=amd64
ENV CGO_ENABLED=0

RUN go build -v -o aws-es-proxy .

FROM harbor.stingray-tooling.com/docker.io-library/alpine:3.15

RUN apk add --no-cache ca-certificates bash

COPY --from=build /src/aws-es-proxy /bin/aws-es-proxy
COPY run.sh /bin/run.sh

ENV ENDPOINT ""
ENV AWS_ACCESS_KEY_ID ""
ENV AWS_SECRET_ACCESS_KEY ""
ENV AWS_ROLE_ARN ""
ENV PORT 9200

EXPOSE $PORT

ENTRYPOINT ["run.sh"]
