package main

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDnsPacketGolden(t *testing.T) {
	pkt := marshalDnsPacket(dnsPacket{
		action: 1, session: 300, msgID: 1, total: 2, current: 1, data: []byte("AB"),
	})
	// Hand-computed proto3: 08 01 | 10 AC 02 | 18 01 | 20 02 | 28 01 | 32 02 4142
	want := []byte{0x08, 0x01, 0x10, 0xAC, 0x02, 0x18, 0x01, 0x20, 0x02, 0x28, 0x01, 0x32, 0x02, 0x41, 0x42}
	if fmt.Sprintf("%x", pkt) != fmt.Sprintf("%x", want) {
		t.Fatalf("marshal = %x, want %x", pkt, want)
	}
	got, err := unmarshalDnsPacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if got.action != 1 || got.session != 300 || got.msgID != 1 || got.total != 2 || got.current != 1 || string(got.data) != "AB" {
		t.Fatalf("unmarshal = %+v", got)
	}
}

func TestDnsPacketZeroOmit(t *testing.T) {
	if len(marshalDnsPacket(dnsPacket{})) != 0 {
		t.Fatal("zero packet must marshal empty (proto3)")
	}
	if _, err := unmarshalDnsPacket([]byte{0x08}); err == nil {
		t.Fatal("truncated varint accepted")
	}
	if _, err := unmarshalDnsPacket([]byte{0x0D, 0x01}); err == nil {
		t.Fatal("bad wire type accepted")
	}
}

func TestDnsChunkBounds(t *testing.T) {
	tr, err := newDNSTransport(Config{
		Profile: "dns", Domains: []string{"dns.example.com"}, DnsServer: "127.0.0.1:53",
		RecordType: "TXT", MaxQueryLength: 120, MaxSubdomainLength: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed := []byte(testUUID + strings.Repeat("A", 200))
	chunks, err := tr.splitData(2, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Fatalf("want multiple chunks, got %d", len(chunks))
	}
	joined := []byte{}
	for _, c := range chunks {
		joined = append(joined, c...)
	}
	if string(joined) != string(sealed) {
		t.Fatal("chunks do not reassemble")
	}
	for i, c := range chunks {
		pkt := marshalDnsPacket(dnsPacket{action: 0, session: 1, msgID: 2, total: uint32(len(chunks)), current: uint32(i), data: c})
		q, err := tr.encodeQuery(pkt)
		if err != nil {
			t.Fatal(err)
		}
		if len(q) > 120 {
			t.Fatalf("query too long: %d", len(q))
		}
		for _, l := range strings.Split(q, ".") {
			if len(l) > 63 {
				t.Fatalf("label too long: %d", len(l))
			}
		}
		if !strings.HasSuffix(q, ".dns.example.com") {
			t.Fatalf("bad suffix: %q", q)
		}
	}
}

// dnsFake is a UDP server mirroring the profile's reply logic: action-first
// answers, order-byte plus padding framing, TXT base64 chunks.
type dnsFake struct {
	t       *testing.T
	conn    *net.UDPConn
	domain  string
	qtype   uint16
	sealed  []byte // expected reassembled upload
	reply   []byte // download payload
	chunk   int    // download Data bytes per packet
	uploads map[uint32]map[uint32][]byte
	totals  map[uint32]uint32
}

func runDNSFake(t *testing.T, domain string, qtype uint16, sealed, reply []byte, chunk int) (string, *dnsFake, func()) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	f := &dnsFake{t: t, conn: conn, domain: domain, qtype: qtype,
		sealed: sealed, reply: reply, chunk: chunk,
		uploads: map[uint32]map[uint32][]byte{}, totals: map[uint32]uint32{}}
	stop := make(chan struct{})
	go f.serve(stop)
	return conn.LocalAddr().String(), f, func() { close(stop); conn.Close() }
}

func (f *dnsFake) serve(stop chan struct{}) {
	buf := make([]byte, 4096)
	for {
		f.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, addr, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-stop:
				return
			default:
				continue
			}
		}
		resp := f.handle(buf[:n])
		if resp != nil {
			f.conn.WriteToUDP(resp, addr)
		}
	}
}

func (f *dnsFake) handle(query []byte) []byte {
	if len(query) < 14 {
		return nil
	}
	off := 12
	var labels []string
	for {
		if off >= len(query) {
			return nil
		}
		n := int(query[off])
		off++
		if n == 0 {
			break
		}
		if off+n > len(query) {
			return nil
		}
		labels = append(labels, string(query[off:off+n]))
		off += n
	}
	qtype := binary.BigEndian.Uint16(query[off:])
	// Strip domain labels, join the rest, base32-decode, unmarshal.
	dlabels := strings.Split(f.domain, ".")
	if len(labels) < len(dlabels)+1 {
		return nil
	}
	joined := strings.Join(labels[:len(labels)-len(dlabels)], "")
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(joined))
	if err != nil {
		f.t.Errorf("fake: base32: %v", err)
		return nil
	}
	pkt, err := unmarshalDnsPacket(raw)
	if err != nil {
		f.t.Errorf("fake: unmarshal: %v", err)
		return nil
	}
	question := query[12:]
	var answers [][]byte
	action := uint32(dnsActionAgentToServer)
	switch pkt.action {
	case dnsActionAgentToServer:
		if f.uploads[pkt.msgID] == nil {
			f.uploads[pkt.msgID] = map[uint32][]byte{}
		}
		f.uploads[pkt.msgID][pkt.current] = pkt.data
		f.totals[pkt.msgID] = pkt.total
		if uint32(len(f.uploads[pkt.msgID])) == pkt.total {
			var full []byte
			for i := uint32(0); i < pkt.total; i++ {
				full = append(full, f.uploads[pkt.msgID][i]...)
			}
			if string(full) != string(f.sealed) {
				f.t.Errorf("fake: upload mismatch: got %d want %d bytes", len(full), len(f.sealed))
			}
			action = dnsActionServerToAgent
		}
	case dnsActionServerToAgent:
		action = dnsActionServerToAgent
		total := (len(f.reply) + f.chunk - 1) / f.chunk
		start := int(pkt.current) * f.chunk
		end := start + f.chunk
		if end > len(f.reply) {
			end = len(f.reply)
		}
		rpkt := marshalDnsPacket(dnsPacket{
			action: dnsActionServerToAgent, session: pkt.session,
			msgID: pkt.msgID, total: uint32(total), current: pkt.current,
			data: f.reply[start:end],
		})
		answers = append(answers, f.packetAnswers(rpkt)...)
	default:
		return nil
	}
	answers = append([][]byte{f.actionAnswer(action, qtype)}, answers...)
	return f.buildReply(query[:2], question, qtype, answers)
}

func (f *dnsFake) actionAnswer(action uint32, qtype uint16) []byte {
	switch qtype {
	case 1:
		return []byte{0x00, 0x00, 0x00, byte(action)}
	case 28:
		b := make([]byte, 16)
		b[15] = byte(action)
		return b
	default:
		s := fmt.Sprintf("%d", action)
		return append([]byte{byte(len(s))}, s...)
	}
}

// packetAnswers frames one marshalled packet like the profile server.
func (f *dnsFake) packetAnswers(pkt []byte) [][]byte {
	switch f.qtype {
	case 1, 28:
		size := 3
		if f.qtype == 28 {
			size = 15
		}
		var out [][]byte
		index := 0
		for i := 0; i < len(pkt); i += size {
			end := i + size
			remaining := 0
			exact := false
			if end > len(pkt) {
				remaining = end - len(pkt)
				end = len(pkt)
			} else if end == len(pkt) {
				exact = true
			}
			chunk := make([]byte, size+1)
			copy(chunk[1:], pkt[i:end])
			chunk[0] = byte(index + 1)
			for j := len(chunk) - 1; j > size-remaining; j-- {
				chunk[j] = byte(remaining)
			}
			out = append(out, chunk)
			index++
			if exact {
				pad := make([]byte, size+1)
				for j := 1; j <= size; j++ {
					pad[j] = byte(size)
				}
				pad[0] = byte(index + 1)
				out = append(out, pad)
				index++
			}
		}
		return out
	default:
		b64 := base64.StdEncoding.EncodeToString(pkt)
		var rdata []byte
		for len(b64) > 0 {
			n := 255
			if n > len(b64) {
				n = len(b64)
			}
			rdata = append(rdata, byte(n))
			rdata = append(rdata, b64[:n]...)
			b64 = b64[n:]
		}
		return [][]byte{rdata}
	}
}

func (f *dnsFake) buildReply(id, question []byte, qtype uint16, rdatas [][]byte) []byte {
	resp := []byte{id[0], id[1], 0x81, 0x80, 0x00, 0x01,
		byte(len(rdatas) >> 8), byte(len(rdatas)), 0x00, 0x00, 0x00, 0x00}
	resp = append(resp, question...)
	for _, rdata := range rdatas {
		resp = append(resp, 0xC0, 0x0C, byte(qtype>>8), byte(qtype), 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, byte(len(rdata)>>8), byte(len(rdata)))
		resp = append(resp, rdata...)
	}
	return resp
}

func TestDNSExchangeTXT(t *testing.T) {
	sealed := []byte(testUUID + `{"action":"checkin","uuid":"` + testUUID + `"}` + strings.Repeat("D", 300))
	reply := []byte(testUUID + `{"action":"checkin","status":"success","id":"` + testUUID + `"}` + strings.Repeat("R", 1500))
	addr, _, stop := runDNSFake(t, "dns.example.com", 16, sealed, reply, 1000)
	defer stop()
	tr, err := newDNSTransport(Config{
		Profile: "dns", Domains: []string{"dns.example.com"}, DnsServer: addr,
		RecordType: "TXT", MaxQueryLength: 200, MaxSubdomainLength: 40,
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := tr.exchange(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(reply) {
		t.Fatalf("reply mismatch: got %d want %d bytes", len(out), len(reply))
	}
}

func TestDNSExchangeA(t *testing.T) {
	sealed := []byte(testUUID + strings.Repeat("D", 120))
	reply := []byte(testUUID + strings.Repeat("R", 300))
	addr, _, stop := runDNSFake(t, "dns.example.com", 1, sealed, reply, 128)
	defer stop()
	tr, err := newDNSTransport(Config{
		Profile: "dns", Domains: []string{"dns.example.com"}, DnsServer: addr,
		RecordType: "A", MaxQueryLength: 180, MaxSubdomainLength: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := tr.exchange(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(reply) {
		t.Fatalf("reply mismatch: got %d want %d bytes", len(out), len(reply))
	}
}

func TestDNSRotation(t *testing.T) {
	tr, err := newDNSTransport(Config{
		Profile: "dns", Domains: []string{"a.example", "b.example", "c.example"},
		DnsServer: "127.0.0.1:53", DomainRotation: "fail-over", FailoverThreshold: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	tr.rotate(false)
	if tr.idx != 0 {
		t.Fatalf("failover moved early: %d", tr.idx)
	}
	tr.rotate(false)
	if tr.idx != 1 {
		t.Fatalf("failover stuck: %d", tr.idx)
	}
	tr.rotate(true)
	tr.rotate(false)
	if tr.idx != 1 {
		t.Fatalf("success did not reset fails: %d", tr.idx)
	}
	tr.rotation = "round-robin"
	tr.rotate(true)
	tr.rotate(true)
	if tr.idx != 0 {
		t.Fatalf("round-robin = %d", tr.idx)
	}
	tr.rotation = "random"
	for i := 0; i < 20; i++ {
		tr.rotate(true)
		if tr.idx < 0 || tr.idx > 2 {
			t.Fatalf("random out of range: %d", tr.idx)
		}
	}
}

func TestDNSRequiresDomain(t *testing.T) {
	if _, err := newDNSTransport(Config{Profile: "dns"}); err == nil {
		t.Fatal("empty domains accepted")
	}
	if _, err := newDNSTransport(Config{Profile: "dns", Domains: []string{"a"}, RecordType: "MX"}); err == nil {
		t.Fatal("bad record type accepted")
	}
}
