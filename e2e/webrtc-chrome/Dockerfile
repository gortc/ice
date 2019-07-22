ARG CI_GO_VERSION
FROM golang:${CI_GO_VERSION}

# Downloading ice deps.
ADD go.mod /ice/go.mod
ADD go.sum /ice/go.sum
WORKDIR /ice
RUN go mod download

# Downloading e2e-specific deps.
ADD e2e/webrtc-chrome/go.mod /ice/e2e/webrtc-chrome/go.mod
ADD e2e/webrtc-chrome/go.sum /ice/e2e/webrtc-chrome/go.sum
WORKDIR /ice/e2e/webrtc-chrome/
RUN go mod download

ADD . /ice

RUN go build -o e2e .

ADD . /ice/
WORKDIR /ice/e2e/webrtc-chrome
ADD e2e/webrtc-chrome/main.go .
RUN go build -o e2e .

FROM yukinying/chrome-headless-browser
COPY --from=0 /ice/e2e/webrtc-chrome .
COPY e2e/webrtc-chrome/static static
ENTRYPOINT ["./e2e", "-b=/usr/bin/google-chrome-unstable", "-timeout=3s"]
