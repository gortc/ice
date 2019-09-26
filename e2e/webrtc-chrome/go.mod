module gortc.io/ice/e2e/webrtc-chrome

go 1.12

require (
	github.com/chromedp/cdproto v0.0.0-20180731224315-b8925c84f3c4 // indirect
	github.com/chromedp/chromedp v0.1.2
	github.com/gorilla/websocket v1.4.1
	github.com/mailru/easyjson v0.0.0-20180730094502-03f2033d19d5 // indirect
	github.com/pkg/errors v0.8.1
	go.uber.org/zap v1.10.0
	golang.org/x/net v0.0.0-20190926025831-c00fd9afed17
	gortc.io/ice v0.7.0
	gortc.io/sdp v0.17.0
)

replace gortc.io/ice v0.0.1 => ../../
