module gortc.io/ice/e2e/webrtc-chrome

go 1.12

require (
	github.com/chromedp/cdproto v0.0.0-20180731224315-b8925c84f3c4
	github.com/chromedp/chromedp v0.1.2
	github.com/disintegration/imaging v1.4.2
	github.com/gorilla/websocket v1.2.0
	github.com/knq/snaker v0.0.0-20180306023312-d9ad1e7f342a
	github.com/knq/sysutil v0.0.0-20180306023629-0218e141a794
	github.com/mailru/easyjson v0.0.0-20180730094502-03f2033d19d5
	github.com/pkg/errors v0.8.1
	golang.org/x/image v0.0.0-20180708004352-c73c2afc3b81
	golang.org/x/net v0.0.0-20190313220215-9f648a60d977
)

replace github.com/gortc/ice => ../../
