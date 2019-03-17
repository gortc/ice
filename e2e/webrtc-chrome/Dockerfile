ARG CI_GO_VERSION
FROM golang:${CI_GO_VERSION}
ADD . /go/src/github.com/gortc/ice/
WORKDIR /go/src/github.com/gortc/ice/e2e/webrtc-chrome
ADD e2e/webrtc-chrome/main.go .
RUN go build -o e2e .

FROM yukinying/chrome-headless-browser
COPY --from=0 /go/src/github.com/gortc/ice/e2e/webrtc-chrome .
COPY e2e/webrtc-chrome/static static
ENTRYPOINT ["./e2e", "-b=/usr/bin/google-chrome-unstable", "-timeout=3s"]
