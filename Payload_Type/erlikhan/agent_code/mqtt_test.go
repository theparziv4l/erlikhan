package main

import (
	"encoding/base64"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeBroker speaks enough MQTT 3.1.1 to exercise one agent exchange:
// CONNACK, SUBACK, PUBACK, then one qos1 PUBLISH carrying replyB64.
func fakeBroker(t *testing.T, replyB64 string) (addr string, got *string, done chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got = new(string)
	done = make(chan struct{})
	go func() {
		defer close(done)
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		fail := func(err error) {
			t.Errorf("broker: %v", err)
		}
		// CONNECT -> CONNACK
		if fixed, body, err := mqttRead(conn); err != nil || fixed != 0x10 || len(body) < 12 {
			fail(err)
			return
		}
		if err := mqttWrite(conn, 0x20, []byte{0x00, 0x00}); err != nil {
			fail(err)
			return
		}
		// SUBSCRIBE -> SUBACK
		fixed, body, err := mqttRead(conn)
		if err != nil || fixed != 0x82 || len(body) < 5 {
			fail(err)
			return
		}
		tlen := int(binary.BigEndian.Uint16(body[2:]))
		subTopic := string(body[4 : 4+tlen])
		if err := mqttWrite(conn, 0x90, []byte{body[0], body[1], 0x01}); err != nil {
			fail(err)
			return
		}
		// PUBLISH -> PUBACK, capture payload
		fixed, body, err = mqttRead(conn)
		if err != nil || fixed != 0x32 {
			fail(err)
			return
		}
		tlen = int(binary.BigEndian.Uint16(body))
		pubTopic := string(body[2 : 2+tlen])
		payload := string(body[2+tlen+2:])
		if err := mqttWrite(conn, 0x40, body[2+tlen:2+tlen+2]); err != nil {
			fail(err)
			return
		}
		*got = pubTopic + "\n" + payload
		// Reply PUBLISH qos1 on the subscribed topic, expect PUBACK.
		reply := mqttString(subTopic)
		reply = append(reply, 0x00, 0x07)
		reply = append(reply, replyB64...)
		if err := mqttWrite(conn, 0x32, reply); err != nil {
			fail(err)
			return
		}
		if fixed, _, err := mqttRead(conn); err != nil || fixed != 0x40 {
			fail(err)
			return
		}
	}()
	return ln.Addr().String(), got, done
}

func mqttTestConfig(addr string) Config {
	host, port := addr[:strings.LastIndex(addr, ":")], addr[strings.LastIndex(addr, ":")+1:]
	return Config{
		Profile: "mqtt", MqttServer: host, MqttPort: port, MqttUseSSL: "False",
		MqttClient: "test", MqttTopic: "base/", MqttMythic: "1", MqttTaskcheck: "2",
	}
}

func TestMQTTExchange(t *testing.T) {
	sealed := []byte(testUUID + `{"action":"checkin"}`)
	reply := []byte(testUUID + `{"action":"checkin","status":"success"}`)
	addr, got, done := fakeBroker(t, base64.StdEncoding.EncodeToString(reply))
	tr, err := newMQTTTransport(mqttTestConfig(addr))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tr.clientID, "test-") || len(tr.clientID) != len("test-")+8 {
		t.Fatalf("client id not suffixed: %q", tr.clientID)
	}
	out, err := tr.exchange(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(reply) {
		t.Fatalf("reply mismatch: %q", out)
	}
	<-done
	lines := strings.SplitN(*got, "\n", 2)
	if lines[0] != "base/2" {
		t.Fatalf("publish topic = %q", lines[0])
	}
	if lines[1] != base64.StdEncoding.EncodeToString(sealed) {
		t.Fatal("publish payload is not base64(sealed)")
	}
}

func TestMQTTRequiresServer(t *testing.T) {
	if _, err := newMQTTTransport(Config{Profile: "mqtt"}); err == nil {
		t.Fatal("empty server accepted")
	}
}
