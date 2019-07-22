ARG CI_GO_VERSION
FROM golang:${CI_GO_VERSION}

# Downloading ice deps.
ADD signaling/go.mod /signaling/go.mod
ADD signaling/go.sum /signaling/go.sum
WORKDIR /signaling
RUN go mod download

ADD signaling/main.go .
RUN go install .

CMD ["signaling"]
