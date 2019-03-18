package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/runner"
	"github.com/gortc/sdp"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/net/websocket"

	"github.com/gortc/ice"
	"github.com/gortc/ice/candidate"
	iceSDP "github.com/gortc/ice/sdp"
)

var (
	bin           = flag.String("b", "/usr/bin/google-chrome", "path to binary")
	headless      = flag.Bool("headless", true, "headless mode")
	httpAddr      = flag.String("addr", "0.0.0.0:8080", "http endpoint to listen")
	signalingAddr = flag.String("signaling", "signaling:2255", "signaling server addr")
	timeout       = flag.Duration("timeout", time.Second*5, "test timeout")
	controlling   = flag.Bool("controlling", false, "agent is controlling")
	browser       = flag.Bool("browser", false, "use browser as ICE agent")
)

func resolve(a string) *net.TCPAddr {
	for i := 0; i < 10; i++ {
		addr, err := net.ResolveTCPAddr("tcp", a)
		if err == nil {
			log.Println("resolved", a, "->", addr)
			return addr
		}
		time.Sleep(time.Millisecond * 100 * time.Duration(i))
	}
	panic("failed to resolve")
}

type dpLogEntry struct {
	Method string `json:"method"`
	Params struct {
		Args []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"args"`
	} `json:"params"`
}

type sdpDescription struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}

type iceDescription struct {
	Candidate string `json:"candidate"`
}

type sdpSignal struct {
	SDP sdpDescription `json:"sdp"`
	ICE iceDescription `json:"ice"`
}

func startNative(ctx context.Context) error {
	const pwd = "P5Ya0tH+WVL4u6rPbt+uMXlk"
	const ufrag = "3BFm"

	if *controlling {
		return errors.New("controlling native client is not implemented")
	}
	signalingURL := fmt.Sprintf("ws://%s/ws", resolve(*signalingAddr))
	ws, err := websocket.Dial(signalingURL, "", "http://127.0.0.1:8080")
	if err != nil {
		return errors.Wrap(err, "failed to initialize ws")
	}
	defer func() {
		_ = ws.Close()
	}()
	messages := make(chan *sdp.Message)
	go func() {
		for {
			buf := make([]byte, 1024)
			n, err := ws.Read(buf)
			if err != nil {
				log.Println("read failed:", err)
				break
			} else {
				sig := new(sdpSignal)
				if err := json.Unmarshal(buf[:n], sig); err != nil {
					log.Fatalln("failed to unmarshal json:", err)
				}
				if sig.SDP.SDP != "" {
					var s sdp.Session
					s, err := sdp.DecodeSession([]byte(sig.SDP.SDP), s)
					if err != nil {
						log.Fatalln("failed to decode SDP:", err)
					}
					d := sdp.NewDecoder(s)
					m := new(sdp.Message)
					if err = d.Decode(m); err != nil {
						log.Println("failed to decode SDP message:", err)
					}
					media := m.Medias[0]
					fmt.Println("ufrag:", media.Attribute("ice-ufrag"), "pwd:", media.Attribute("ice-pwd"))
					messages <- m
				} else if sig.ICE.Candidate != "" {
					var c iceSDP.Candidate
					if err := iceSDP.ParseAttribute([]byte(sig.ICE.Candidate), &c); err != nil {
						log.Fatalln("failed to parse ICE candidate:", err)
					}
					log.Println("parsed ICE candidate:", c.ConnectionAddress, c.ComponentID)
				} else {
					log.Printf("got %s", buf[:n])
				}
			}
		}
	}()
	log.Println("notifying about initialization")
	_, port, err := net.SplitHostPort(*httpAddr)
	if err != nil {
		return err
	}
	postURL := fmt.Sprintf("http://127.0.0.1:%s/initialized", port)
	resp, err := http.Post(postURL, "text/plain", nil)
	if err != nil {
		return errors.Wrap(err, "failed to POST /initialized")
	}
	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("bad code %d", resp.StatusCode)
	}
	logger, err := zap.NewDevelopment()
	if err != nil {
		return err
	}
	a, err := ice.NewAgent(ice.WithLogger(logger), ice.WithRole(ice.Controlled))
	if err != nil {
		return err
	}
	defer func() {
		if err := a.Close(); err != nil {
			log.Println("failed to close agent:", err)
		}
	}()
	a.SetLocalCredentials(ufrag, pwd)
	if err = a.GatherCandidates(); err != nil {
		return errors.Wrap(err, "failed to gather candidates")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case m := <-messages:
		log.Println("got offer:", len(m.Medias), "stream(s)")
		media := m.Medias[0]
		var candidates []ice.Candidate
		for _, rawCandidate := range media.Attributes.Values("candidate") {
			var c iceSDP.Candidate
			if err := iceSDP.ParseAttribute([]byte(rawCandidate), &c); err != nil {
				log.Fatalln("failed to parse ICE candidate:", err)
			}
			cnd := ice.Candidate{
				Type:        candidate.Host,
				ComponentID: c.ComponentID,
				Addr: ice.Addr{
					IP:   c.ConnectionAddress.IP,
					Port: c.Port,
				},
				Priority: c.Priority,
			}
			cnd.Foundation = ice.Foundation(&cnd, ice.Addr{})
			candidates = append(candidates, cnd)
		}
		if err := a.AddRemoteCandidates(candidates); err != nil {
			log.Fatalln("failed to add remote candidates:", err)
		}
		a.SetRemoteCredentials(media.Attribute("ice-ufrag"), media.Attribute("ice-password"))
		if err := a.PrepareChecklistSet(); err != nil {
			log.Fatalln("failed to prepare sets:", err)
		}
		log.Println("checklist init OK")
	}
	<-ctx.Done()
	return nil
}

func startBrowser(ctx context.Context) error {
	c, err := chromedp.New(ctx, chromedp.WithLog(func(s string, i ...interface{}) {
		var entry dpLogEntry
		if err := json.Unmarshal([]byte(i[0].(string)), &entry); err != nil {
			log.Fatalln(err)
		}
		if entry.Method == "Runtime.consoleAPICalled" {
			for _, a := range entry.Params.Args {
				log.Println("agent:", a.Value)
			}
		}
	}), chromedp.WithRunnerOptions(
		runner.Path(*bin), runner.DisableGPU, runner.Flag("headless", *headless),
	))
	if err != nil {
		return errors.Wrap(err, "failed to create chrome")
	}
	if err := c.Run(ctx, chromedp.Navigate("http://"+*httpAddr)); err != nil {
		return errors.Wrap(err, "failed to navigate")
	}
	return nil
}

func main() {
	flag.Parse()
	fmt.Println("bin", *bin, "addr", *httpAddr, "timeout", *timeout)
	fs := http.FileServer(http.Dir("static"))
	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		log.Println("http:", request.Method, request.URL.Path, request.RemoteAddr)
		fs.ServeHTTP(writer, request)
	})
	gotSuccess := make(chan struct{})
	initialized := make(chan struct{})
	http.HandleFunc("/initialized", func(writer http.ResponseWriter, request *http.Request) {
		log.Println("http:", request.Method, request.URL.Path, request.RemoteAddr)
		switch request.Method {
		case http.MethodPost:
			// Should be called by browser after initializing websocket conn.
			initialized <- struct{}{}
		case http.MethodGet:
			// Should be called by controlling agent to wait until controlled init.
			<-initialized
		}
	})
	http.HandleFunc("/success", func(writer http.ResponseWriter, request *http.Request) {
		gotSuccess <- struct{}{}
	})
	http.HandleFunc("/config", func(writer http.ResponseWriter, request *http.Request) {
		log.Println("http:", request.Method, request.URL.Path, request.RemoteAddr)
		if *controlling {
			// Waiting for controlled agent to start.
			log.Println("waiting for controlled agent init")
			getAddr := resolve("turn-controlled:8080")
			getURL := fmt.Sprintf("http://%s/initialized", getAddr)
			res, getErr := http.Get(getURL)
			if getErr != nil {
				log.Fatalln("failed to get:", getErr)
			}
			if res.StatusCode != http.StatusOK {
				log.Fatalln("bad status", res.Status)
			}
			log.Println("controlled agent initialized")
		}
		encoder := json.NewEncoder(writer)
		if encodeErr := encoder.Encode(struct {
			Controlling bool   `json:"controlling"`
			Signaling   string `json:"signaling"`
		}{
			Controlling: *controlling,
			Signaling:   fmt.Sprintf("ws://%s/ws", resolve(*signalingAddr)),
		}); encodeErr != nil {
			log.Fatal(encodeErr)
		}
	})
	go func() {
		if err := http.ListenAndServe(*httpAddr, nil); err != nil {
			log.Fatalln("failed to listen:", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if *browser {
		log.Println("running in browser")
		if err := startBrowser(ctx); err != nil {
			log.Fatalln("failed to run in browser mode:", err)
		}
	} else {
		log.Println("running in native mode")
		if err := startNative(ctx); err != nil {
			log.Fatalln("failed to run native:", err)
		}
	}
	select {
	case <-gotSuccess:
		log.Println("succeeded")
	case <-ctx.Done():
		log.Fatalln(ctx.Err())
	}
}
