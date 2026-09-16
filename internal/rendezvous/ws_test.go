package rendezvous

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"
)

// wsEcho stands up a server that echoes every byte it receives, so a client
// can exercise the framing in both directions.
func wsEcho(t *testing.T) *Endpoint {
	t.Helper()
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		t.Setenv(key, "")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := ServerHandshake(w, r)
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	})
	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)

	u, _ := url.Parse(hs.URL)
	port, _ := strconv.Atoi(u.Port())
	return &Endpoint{Host: u.Hostname(), TLSPort: 1, HTTPPort: port, Path: "/ws"}
}

func TestWebSocketRoundTrip(t *testing.T) {
	ep := wsEcho(t)
	conn, err := ep.DialRung(context.Background(), RungHTTPDirect)
	if err != nil {
		t.Fatalf("dialling: %v", err)
	}
	defer conn.Close()

	// Sizes spanning all three RFC 6455 length encodings: 7-bit, 16-bit and
	// the 64-bit extended form.
	for _, size := range []int{1, 125, 126, 1000, 70000} {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i)
		}
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("writing %d bytes: %v", size, err)
		}
		got := make([]byte, size)
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("reading %d bytes back: %v", size, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("payload of %d bytes came back changed", size)
		}
	}
}

// TestWebSocketDoesNotMutateCaller guards the masking path: a client must mask
// outbound frames, and must do so without scribbling on the caller's buffer.
func TestWebSocketDoesNotMutateCaller(t *testing.T) {
	ep := wsEcho(t)
	conn, err := ep.DialRung(context.Background(), RungHTTPDirect)
	if err != nil {
		t.Fatalf("dialling: %v", err)
	}
	defer conn.Close()

	payload := []byte("this buffer belongs to the caller")
	original := append([]byte(nil), payload...)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if !bytes.Equal(payload, original) {
		t.Error("Write masked the caller's buffer in place")
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("echo returned %q", got)
	}
}

// TestWebSocketPingKeepsConnectionUsable checks that a ping in flight does not
// disturb the byte stream, which is what the keepalive relies on.
func TestWebSocketPingKeepsConnectionUsable(t *testing.T) {
	ep := wsEcho(t)
	conn, err := ep.DialRung(context.Background(), RungHTTPDirect)
	if err != nil {
		t.Fatalf("dialling: %v", err)
	}
	defer conn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			if err := conn.Ping(); err != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	payload := []byte("data alongside pings")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("writing: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("reading: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("stream corrupted by pings: %q", got)
	}
	wg.Wait()
}

func TestWebSocketRejectsNonUpgrade(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if _, err := ServerHandshake(w, r); err != nil {
			http.Error(w, "no", http.StatusBadRequest)
		}
	})
	hs := httptest.NewServer(mux)
	defer hs.Close()

	resp, err := http.Get(hs.URL + "/ws")
	if err != nil {
		t.Fatalf("plain GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Error("a plain GET was upgraded")
	}
}

func TestControlMessageRoundTrip(t *testing.T) {
	in := &Message{Type: MsgPaired, Role: RolePublisher, PunchInMS: 250, Reason: "x"}
	buf, err := EncodeMessage(in)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	out, err := DecodeMessage(buf)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if out.Type != in.Type || out.Role != in.Role || out.PunchInMS != in.PunchInMS {
		t.Errorf("message changed in transit: %+v", out)
	}
	if _, err := DecodeMessage([]byte("{}")); err == nil {
		t.Error("a message with no type was accepted")
	}
	if _, err := DecodeMessage(make([]byte, MaxControlFrame+1)); err == nil {
		t.Error("an oversized control message was accepted")
	}
}
