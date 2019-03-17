ARG CI_GO_VERSION
FROM golang:${CI_GO_VERSION}
ADD vendor /go/src/github.com/gortc/gortcd/e2e/webrtc-chrome/vendor
WORKDIR /go/src/github.com/gortc/gortcd/e2e/webrtc-chrome/
ADD signaling/main.go signaling/main.go
WORKDIR /go/src/github.com/gortc/gortcd/e2e/webrtc-chrome/signaling
RUN go install .
CMD ["signaling"]
