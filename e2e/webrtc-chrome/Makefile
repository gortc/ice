start-controlled:
	./webrtc-chrome -addr 127.0.0.1:5568 -signaling 127.0.0.1:2255 -timeout 300s
start-controlling:
	./webrtc-chrome -browser -headless=false -addr 127.0.0.1:5569 -signaling 127.0.0.1:2255 -controlling -timeout 300s -controlled 127.0.0.1:5568
start-signalling:
	go run signaling/main.go
