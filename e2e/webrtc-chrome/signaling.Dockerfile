ARG CI_GO_VERSION
FROM golang:${CI_GO_VERSION}
RUN mkdir /signaling
ADD signaling/main.go /signaling/main.go
WORKDIR /signaling
RUN go install .
CMD ["signaling"]
