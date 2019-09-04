module gortc.io/ice/e2e/webrtc-chrome

go 1.12

require (
	github.com/chromedp/cdproto v0.0.0-20180731224315-b8925c84f3c4 // indirect
	github.com/chromedp/chromedp v0.1.2
	github.com/gorilla/websocket v1.4.1
	github.com/mailru/easyjson v0.0.0-20190626092158-b2ccc519800e // indirect
	github.com/pkg/errors v0.8.1
	go.uber.org/zap v1.10.0
	golang.org/x/net v0.0.0-20190313220215-9f648a60d977
	gortc.io/ice v0.0.1
	gortc.io/sdp v0.17.0
)

replace gortc.io/ice v0.0.1 => ../../
