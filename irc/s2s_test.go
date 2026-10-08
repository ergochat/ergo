// Copyright (c) 2026 Ergo Developers
// released under the MIT license

package irc

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ergochat/ergo/irc/logger"
	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/utils"
)

func createTestServer(t *testing.T, sid, name string, linkConfigs map[string]LinkConfig) *Server {
	t.Helper()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	var linksYAML strings.Builder
	if len(linkConfigs) > 0 {
		linksYAML.WriteString("    links:\n")
		for linkName, lc := range linkConfigs {
			linksYAML.WriteString(fmt.Sprintf("        %s:\n", linkName))
			if lc.SID != "" {
				linksYAML.WriteString(fmt.Sprintf("            sid: %s\n", lc.SID))
			}
			if lc.SendPassword != "" {
				linksYAML.WriteString(fmt.Sprintf("            send-password: %s\n", lc.SendPassword))
			}
			if lc.ReceivePassword != "" {
				linksYAML.WriteString(fmt.Sprintf("            receive-password: %s\n", lc.ReceivePassword))
			}
			if lc.Hostname != "" {
				linksYAML.WriteString(fmt.Sprintf("            hostname: %s\n", lc.Hostname))
			}
			if lc.Port != 0 {
				linksYAML.WriteString(fmt.Sprintf("            port: %d\n", lc.Port))
			}
		}
	}

	configYAML := fmt.Sprintf(`
network:
    name: TestNet
server:
    name: %s
    sid: "%s"
    casemapping: ascii
    max-sendq: "10M"
    listeners:
        "127.0.0.1:0":
%s
datastore:
    path: %s
limits:
    nicklen: 32
    identlen: 20
    realnamelen: 150
    channellen: 64
    awaylen: 390
    kicklen: 390
    topiclen: 390
    chan-list-modes: 60
`, name, sid, linksYAML.String(), dbPath)

	configFile := filepath.Join(tempDir, "ircd.yaml")
	if err := os.WriteFile(configFile, []byte(configYAML), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	config, err := LoadConfig(configFile)
	if err != nil {
		t.Fatalf("failed to load test config: %v", err)
	}

	logman, err := logger.NewManager(nil)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	server, err := NewServer(config, logman)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	t.Cleanup(func() {
		server.Shutdown()
	})

	return server
}

type testIRCClient struct {
	conn       net.Conn
	reader     *bufio.Reader
	nick       string
	server     *Server
	linesChan  chan string
	closedChan chan struct{}
}

func newTestIRCClient(t *testing.T, server *Server, nick string) *testIRCClient {
	t.Helper()
	clientSide, serverSide := net.Pipe()

	tc := &testIRCClient{
		conn:       clientSide,
		reader:     bufio.NewReader(clientSide),
		nick:       nick,
		server:     server,
		linesChan:  make(chan string, 100),
		closedChan: make(chan struct{}),
	}

	go func() {
		wConn := &utils.WrappedConn{Conn: serverSide}
		server.RunClient(NewIRCStreamConn(wConn), nil)
	}()

	go func() {
		defer close(tc.closedChan)
		for {
			line, err := tc.reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			tc.linesChan <- line
		}
	}()

	// Perform registration
	tc.SendLine("NICK " + nick)
	tc.SendLine("USER " + nick + " 0 * :" + nick)

	// Wait for 001 (RPL_WELCOME)
	for {
		line := tc.ReadLineTimeout(2 * time.Second)
		if line == "" {
			t.Fatalf("timeout waiting for 001 welcome for client %s", nick)
		}
		if strings.Contains(line, " 001 ") {
			break
		}
	}

	t.Cleanup(func() {
		tc.Close()
	})

	return tc
}

func (tc *testIRCClient) SendLine(line string) {
	_, _ = tc.conn.Write([]byte(line + "\r\n"))
}

func (tc *testIRCClient) ReadLineTimeout(timeout time.Duration) string {
	select {
	case line := <-tc.linesChan:
		return line
	case <-time.After(timeout):
		return ""
	case <-tc.closedChan:
		return ""
	}
}

func (tc *testIRCClient) Close() {
	_ = tc.conn.Close()
}

func linkTestServers(t *testing.T, s1, s2 *Server, cfg1, cfg2 *LinkConfig) (*ServerLink, *ServerLink) {
	t.Helper()
	pipe1, pipe2 := net.Pipe()

	link1 := NewServerLink(s1, NewIRCStreamConn(&utils.WrappedConn{Conn: pipe1}), cfg1, true)
	link2 := NewServerLink(s2, NewIRCStreamConn(&utils.WrappedConn{Conn: pipe2}), cfg2, false)

	go link1.WriteLoop()
	go link1.ReadLoop()

	sendPass := "*"
	if cfg2 != nil && cfg2.SendPassword != "" {
		sendPass = cfg2.SendPassword
	}
	link2.SendLine(fmt.Sprintf("PASS %s TS 6 :%s", sendPass, s2.SID()))
	link2.SendLine("CAPAB :QS EX CHW IE ENCAP EUID TB KNOCK")
	link2.SendLine(fmt.Sprintf("SERVER %s 1 :%s", s2.name, s2.name))
	link2.SendLine(fmt.Sprintf("SVINFO 6 6 0 :%d", time.Now().Unix()))

	go link2.WriteLoop()
	go link2.ReadLoop()

	// Wait for both sides to finish handshake and burst
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if link1.HandshakeDone() && link2.HandshakeDone() && link1.BurstDone() && link2.BurstDone() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !link1.HandshakeDone() || !link2.HandshakeDone() || !link1.BurstDone() || !link2.BurstDone() {
		t.Fatalf("link failed between %s and %s: h1=%v h2=%v b1=%v b2=%v", s1.SID(), s2.SID(), link1.HandshakeDone(), link2.HandshakeDone(), link1.BurstDone(), link2.BurstDone())
	}

	return link1, link2
}

func TestS2SUIDGenerator(t *testing.T) {
	if !IsValidSID("001") || !IsValidSID("ABC") || !IsValidSID("12Z") {
		t.Errorf("expected valid SIDs")
	}
	if IsValidSID("00") || IsValidSID("0001") || IsValidSID("00!") || IsValidSID("") {
		t.Errorf("expected invalid SIDs")
	}

	if !IsValidUID("001AAAAAA") || !IsValidUID("ABC123456") {
		t.Errorf("expected valid UIDs")
	}
	if IsValidUID("001") || IsValidUID("001AAAAAAA") || IsValidUID("00!AAAAAA") || IsValidUID("") {
		t.Errorf("expected invalid UIDs")
	}

	gen := NewUIDGenerator("10A")
	uid1 := gen.Next()
	uid2 := gen.Next()

	if len(uid1) != 9 || !strings.HasPrefix(uid1, "10A") {
		t.Errorf("unexpected UID format: %s", uid1)
	}
	if len(uid2) != 9 || !strings.HasPrefix(uid2, "10A") {
		t.Errorf("unexpected UID format: %s", uid2)
	}
	if uid1 == uid2 {
		t.Errorf("generated duplicate UIDs: %s == %s", uid1, uid2)
	}
}

func TestS2SHandshake(t *testing.T) {
	s1 := createTestServer(t, "100", "srv1.test", nil)
	s2 := createTestServer(t, "200", "srv2.test", nil)

	link1, link2 := linkTestServers(t, s1, s2, nil, nil)

	if !link1.HandshakeDone() || !link2.HandshakeDone() {
		t.Fatalf("expected handshake to complete on both sides")
	}

	// Verify server nodes registered
	node2On1 := s1.S2S().GetServerBySID("200")
	if node2On1 == nil || node2On1.Name != "srv2.test" {
		t.Errorf("server 1 missing node for server 2: %v", node2On1)
	}

	node1On2 := s2.S2S().GetServerBySID("100")
	if node1On2 == nil || node1On2.Name != "srv1.test" {
		t.Errorf("server 2 missing node for server 1: %v", node1On2)
	}
}

func TestS2SHandshakePasswordAuth(t *testing.T) {
	links1 := map[string]LinkConfig{
		"srv2": {
			SID:             "200",
			ReceivePassword: "secret-recv-pass",
			SendPassword:    "secret-send-pass",
		},
	}
	links2Valid := map[string]LinkConfig{
		"srv1": {
			SID:             "100",
			ReceivePassword: "secret-send-pass",
			SendPassword:    "secret-recv-pass",
		},
	}
	links2Invalid := map[string]LinkConfig{
		"srv1": {
			SID:             "100",
			ReceivePassword: "wrong-password",
			SendPassword:    "wrong-password",
		},
	}

	// Test valid password handshake
	s1 := createTestServer(t, "100", "srv1.test", links1)
	s2 := createTestServer(t, "200", "srv2.test", links2Valid)

	cfg1 := &LinkConfig{ReceivePassword: "secret-recv-pass", SendPassword: "secret-send-pass"}
	cfg2 := &LinkConfig{ReceivePassword: "secret-send-pass", SendPassword: "secret-recv-pass"}

	link1, link2 := linkTestServers(t, s1, s2, cfg1, cfg2)
	if !link1.HandshakeDone() || !link2.HandshakeDone() {
		t.Errorf("expected authenticated handshake to succeed")
	}

	// Test invalid password handshake
	s1Bad := createTestServer(t, "100", "srv1.test", links1)
	s2Bad := createTestServer(t, "200", "srv2.test", links2Invalid)

	pipe1, pipe2 := net.Pipe()
	l1 := NewServerLink(s1Bad, NewIRCStreamConn(&utils.WrappedConn{Conn: pipe1}), cfg1, true)
	cfg2Bad := &LinkConfig{ReceivePassword: "wrong", SendPassword: "wrong"}
	l2 := NewServerLink(s2Bad, NewIRCStreamConn(&utils.WrappedConn{Conn: pipe2}), cfg2Bad, false)

	go l1.WriteLoop()
	go l1.ReadLoop()

	l2.SendLine(fmt.Sprintf("PASS wrong TS 6 :%s", s2Bad.SID()))
	l2.SendLine("CAPAB :QS EX CHW IE ENCAP EUID TB KNOCK")
	l2.SendLine(fmt.Sprintf("SERVER %s 1 :%s", s2Bad.name, s2Bad.name))
	l2.SendLine(fmt.Sprintf("SVINFO 6 6 0 :%d", time.Now().Unix()))

	go l2.WriteLoop()
	go l2.ReadLoop()

	time.Sleep(100 * time.Millisecond)

	if l1.HandshakeDone() {
		t.Errorf("expected bad password handshake to fail on server 1")
	}
}

func TestS2SClientPropagationAndLookup(t *testing.T) {
	s1 := createTestServer(t, "100", "srv1.test", nil)
	s2 := createTestServer(t, "200", "srv2.test", nil)

	linkTestServers(t, s1, s2, nil, nil)

	alice := newTestIRCClient(t, s1, "alice")
	bob := newTestIRCClient(t, s2, "bob")

	// Wait for client propagation
	time.Sleep(150 * time.Millisecond)

	// Verify alice is visible on server 2 by nick and UID
	aliceClientOn2 := s2.clients.Get("alice")
	if aliceClientOn2 == nil {
		t.Fatalf("alice not found on server 2 by nick")
	}
	if !aliceClientOn2.IsRemote() {
		t.Errorf("expected alice to be marked remote on server 2")
	}
	if aliceClientOn2.ServerSID() != "100" {
		t.Errorf("expected alice server SID 100, got %s", aliceClientOn2.ServerSID())
	}
	if s2.clients.GetByUID(aliceClientOn2.UID()) != aliceClientOn2 {
		t.Errorf("alice lookup by UID failed on server 2")
	}

	// Verify bob is visible on server 1 by nick and UID
	bobClientOn1 := s1.clients.Get("bob")
	if bobClientOn1 == nil {
		t.Fatalf("bob not found on server 1 by nick")
	}
	if !bobClientOn1.IsRemote() {
		t.Errorf("expected bob to be marked remote on server 1")
	}
	if bobClientOn1.ServerSID() != "200" {
		t.Errorf("expected bob server SID 200, got %s", bobClientOn1.ServerSID())
	}
	if s1.clients.GetByUID(bobClientOn1.UID()) != bobClientOn1 {
		t.Errorf("bob lookup by UID failed on server 1")
	}

	_ = alice
	_ = bob
}

func TestS2SSharedChannelAndMessaging(t *testing.T) {
	s1 := createTestServer(t, "100", "srv1.test", nil)
	s2 := createTestServer(t, "200", "srv2.test", nil)

	linkTestServers(t, s1, s2, nil, nil)

	alice := newTestIRCClient(t, s1, "alice")
	bob := newTestIRCClient(t, s2, "bob")

	time.Sleep(100 * time.Millisecond)

	// Alice joins #general
	alice.SendLine("JOIN #general")
	time.Sleep(100 * time.Millisecond)

	// Bob joins #general
	bob.SendLine("JOIN #general")
	time.Sleep(100 * time.Millisecond)

	// Verify both channels exist on both servers and have members
	ch1 := s1.channels.Get("#general")
	ch2 := s2.channels.Get("#general")
	if ch1 == nil || ch2 == nil {
		t.Fatalf("channel #general not found on both servers: ch1=%v, ch2=%v", ch1, ch2)
	}

	if len(ch1.Members()) != 2 || len(ch2.Members()) != 2 {
		t.Errorf("expected 2 members on both servers: ch1=%d, ch2=%d", len(ch1.Members()), len(ch2.Members()))
	}

	// Flush lines from registration/joins
	for {
		if alice.ReadLineTimeout(20*time.Millisecond) == "" {
			break
		}
	}
	for {
		if bob.ReadLineTimeout(20*time.Millisecond) == "" {
			break
		}
	}

	// Alice sends message to #general
	alice.SendLine("PRIVMSG #general :Hello everyone!")
	bobLine := bob.ReadLineTimeout(1 * time.Second)
	if !strings.Contains(bobLine, "PRIVMSG #general :Hello everyone!") {
		t.Errorf("bob did not receive alice's channel message, got: %s", bobLine)
	}

	// Bob sends message to #general
	bob.SendLine("PRIVMSG #general :Hi Alice!")
	aliceLine := alice.ReadLineTimeout(1 * time.Second)
	if !strings.Contains(aliceLine, "PRIVMSG #general :Hi Alice!") {
		t.Errorf("alice did not receive bob's channel message, got: %s", aliceLine)
	}

	// Alice sends private message to Bob by nick
	alice.SendLine("PRIVMSG bob :Private message from Alice")
	bobPrivLine := bob.ReadLineTimeout(1 * time.Second)
	if !strings.Contains(bobPrivLine, "PRIVMSG bob :Private message from Alice") {
		t.Errorf("bob did not receive direct privmsg, got: %s", bobPrivLine)
	}

	// Bob sends private message to Alice by nick
	bob.SendLine("PRIVMSG alice :Private reply from Bob")
	alicePrivLine := alice.ReadLineTimeout(1 * time.Second)
	if !strings.Contains(alicePrivLine, "PRIVMSG alice :Private reply from Bob") {
		t.Errorf("alice did not receive direct privmsg reply, got: %s", alicePrivLine)
	}
}

func TestS2STopicAndModes(t *testing.T) {
	s1 := createTestServer(t, "100", "srv1.test", nil)
	s2 := createTestServer(t, "200", "srv2.test", nil)

	linkTestServers(t, s1, s2, nil, nil)

	alice := newTestIRCClient(t, s1, "alice")
	bob := newTestIRCClient(t, s2, "bob")

	time.Sleep(100 * time.Millisecond)

	alice.SendLine("JOIN #topic_test")
	bob.SendLine("JOIN #topic_test")
	time.Sleep(100 * time.Millisecond)

	// Flush output
	for {
		if bob.ReadLineTimeout(20*time.Millisecond) == "" {
			break
		}
	}

	// Alice sets topic
	alice.SendLine("TOPIC #topic_test :New awesome topic")
	time.Sleep(100 * time.Millisecond)

	bobTopicLine := bob.ReadLineTimeout(1 * time.Second)
	if !strings.Contains(bobTopicLine, "TOPIC #topic_test :New awesome topic") {
		t.Errorf("bob did not receive topic update, got: %s", bobTopicLine)
	}

	ch2 := s2.channels.Get("#topic_test")
	if ch2 == nil || ch2.Topic() != "New awesome topic" {
		t.Errorf("server 2 channel topic not updated properly: %v", ch2)
	}
}

func TestS2SNickChange(t *testing.T) {
	s1 := createTestServer(t, "100", "srv1.test", nil)
	s2 := createTestServer(t, "200", "srv2.test", nil)

	linkTestServers(t, s1, s2, nil, nil)

	alice := newTestIRCClient(t, s1, "alice")
	bob := newTestIRCClient(t, s2, "bob")

	time.Sleep(100 * time.Millisecond)

	alice.SendLine("JOIN #nick_test")
	bob.SendLine("JOIN #nick_test")
	time.Sleep(100 * time.Millisecond)

	// Flush bob lines
	for {
		if bob.ReadLineTimeout(20*time.Millisecond) == "" {
			break
		}
	}

	// Alice changes nick to alice_new
	alice.SendLine("NICK alice_new")
	time.Sleep(100 * time.Millisecond)

	// Bob should receive NICK change notification
	bobNickLine := bob.ReadLineTimeout(1 * time.Second)
	if !strings.Contains(bobNickLine, "NICK alice_new") && !strings.Contains(bobNickLine, "NICK :alice_new") {
		t.Errorf("bob did not receive nick change notification, got: %s", bobNickLine)
	}

	// Lookup set on server 2 should now have alice_new and not alice
	if s2.clients.Get("alice") != nil {
		t.Errorf("old nick 'alice' still present in server 2 lookup set")
	}
	if s2.clients.Get("alice_new") == nil {
		t.Errorf("new nick 'alice_new' not found in server 2 lookup set")
	}
}

func TestS2SNetsplit(t *testing.T) {
	s1 := createTestServer(t, "100", "srv1.test", nil)
	s2 := createTestServer(t, "200", "srv2.test", nil)

	link1, link2 := linkTestServers(t, s1, s2, nil, nil)

	alice := newTestIRCClient(t, s1, "alice")
	bob := newTestIRCClient(t, s2, "bob")

	time.Sleep(100 * time.Millisecond)

	alice.SendLine("JOIN #split_test")
	bob.SendLine("JOIN #split_test")
	time.Sleep(100 * time.Millisecond)

	// Flush alice's messages
	for {
		if alice.ReadLineTimeout(20*time.Millisecond) == "" {
			break
		}
	}

	// Close the link (triggering netsplit)
	link1.Close("Link closed")
	link2.Close("Link closed")

	time.Sleep(200 * time.Millisecond)

	// Alice should receive netsplit QUIT for Bob
	splitLine := alice.ReadLineTimeout(1 * time.Second)
	if !strings.Contains(splitLine, "QUIT") || !strings.Contains(splitLine, "srv2.test") {
		t.Errorf("alice did not receive netsplit QUIT for bob, got: %s", splitLine)
	}

	// Bob should no longer be in server 1's clients
	if s1.clients.Get("bob") != nil {
		t.Errorf("bob still present in server 1 clients after netsplit")
	}

	// Server 2 node should no longer be registered in server 1
	if s1.S2S().GetServerBySID("200") != nil {
		t.Errorf("server 2 node still registered in server 1 after netsplit")
	}
}

func TestS2SAway(t *testing.T) {
	s1 := createTestServer(t, "100", "srv1.test", nil)
	s2 := createTestServer(t, "200", "srv2.test", nil)

	linkTestServers(t, s1, s2, nil, nil)

	_ = newTestIRCClient(t, s1, "alice")
	bob := newTestIRCClient(t, s2, "bob")

	time.Sleep(100 * time.Millisecond)

	// Bob sets AWAY
	bob.SendLine("AWAY :Taking a nap")
	time.Sleep(100 * time.Millisecond)

	bobOn1 := s1.clients.Get("bob")
	if bobOn1 == nil {
		t.Fatalf("bob not found on server 1")
	}
	if bobOn1.AwayMessage() != "Taking a nap" {
		t.Errorf("expected away message 'Taking a nap', got '%s'", bobOn1.AwayMessage())
	}

	// Bob unsets AWAY
	bob.SendLine("AWAY")
	time.Sleep(100 * time.Millisecond)

	if bobOn1.AwayMessage() != "" {
		t.Errorf("expected empty away message, got '%s'", bobOn1.AwayMessage())
	}
}

func TestS2SKill(t *testing.T) {
	s1 := createTestServer(t, "100", "srv1.test", nil)
	s2 := createTestServer(t, "200", "srv2.test", nil)

	linkTestServers(t, s1, s2, nil, nil)

	alice := newTestIRCClient(t, s1, "alice")
	bob := newTestIRCClient(t, s2, "bob")

	time.Sleep(100 * time.Millisecond)

	alice.SendLine("JOIN #kill_test")
	bob.SendLine("JOIN #kill_test")
	time.Sleep(100 * time.Millisecond)

	// Flush alice lines
	for {
		if alice.ReadLineTimeout(20*time.Millisecond) == "" {
			break
		}
	}

	// Server 1 kills remote client bob
	bobOn1 := s1.clients.Get("bob")
	if bobOn1 == nil {
		t.Fatalf("bob not found on server 1")
	}
	s1.S2S().BroadcastKill("100", bobOn1, "Rule violation")

	time.Sleep(150 * time.Millisecond)

	// Alice should receive QUIT/Kill notice
	quitLine := alice.ReadLineTimeout(1 * time.Second)
	if !strings.Contains(quitLine, "QUIT") || !strings.Contains(quitLine, "Killed") {
		t.Errorf("alice did not receive kill QUIT for bob, got: %s", quitLine)
	}

	// Bob should be removed from both servers
	if s1.clients.Get("bob") != nil {
		t.Errorf("bob still in server 1 after kill")
	}
	if s2.clients.Get("bob") != nil {
		t.Errorf("bob still in server 2 after kill")
	}
}

func TestS2SNickCollision(t *testing.T) {
	s1 := createTestServer(t, "100", "srv1.test", nil)
	s2 := createTestServer(t, "200", "srv2.test", nil)

	_, link2 := linkTestServers(t, s1, s2, nil, nil)

	alice := newTestIRCClient(t, s1, "collision_nick")
	time.Sleep(100 * time.Millisecond)

	aliceOn1 := s1.clients.Get("collision_nick")
	if aliceOn1 == nil {
		t.Fatalf("collision_nick not found on server 1")
	}

	// Simulate incoming UID from server 2 with older timestamp
	olderTS := time.Now().Add(-10 * time.Minute).Unix()
	// UID <nick> <hops> <ts> <modes> <user> <host> <ip> <uid> :<realname>
	olderUIDMsg := fmt.Sprintf("UID collision_nick 1 %d +i remotehost remotenick 127.0.0.1 200AAA999 :Remote Older", olderTS)
	link2.SendLine(olderUIDMsg)

	time.Sleep(150 * time.Millisecond)

	// Local alice should have been killed/disconnected due to collision with older TS
	select {
	case <-alice.closedChan:
		// Expected: local connection disconnected on collision kill
	case <-time.After(1 * time.Second):
		t.Errorf("local alice was not disconnected after nick collision")
	}

	// The client registered under collision_nick on server 1 should now be the remote older one
	current := s1.clients.Get("collision_nick")
	if current == nil || current.UID() != "200AAA999" {
		t.Errorf("expected remote older client with UID 200AAA999 on server 1, got: %v", current)
	}
}

func TestS2SMultiHopRouting(t *testing.T) {
	s1 := createTestServer(t, "100", "srv1.test", nil)
	s2 := createTestServer(t, "200", "srv2.test", nil)
	s3 := createTestServer(t, "300", "srv3.test", nil)

	// Link S1 <-> S2 and S2 <-> S3
	linkTestServers(t, s1, s2, nil, nil)
	linkTestServers(t, s2, s3, nil, nil)

	time.Sleep(100 * time.Millisecond)

	// S1 should know about S3 via S2
	node3On1 := s1.S2S().GetServerBySID("300")
	if node3On1 == nil {
		t.Fatalf("server 1 does not know about server 3")
	}
	if node3On1.NextHop.RemoteSID() != "200" {
		t.Errorf("expected next hop to server 3 from server 1 to be 200, got: %s", node3On1.NextHop.RemoteSID())
	}

	// S3 should know about S1 via S2
	node1On3 := s3.S2S().GetServerBySID("100")
	if node1On3 == nil {
		t.Fatalf("server 3 does not know about server 1")
	}
	if node1On3.NextHop.RemoteSID() != "200" {
		t.Errorf("expected next hop to server 1 from server 3 to be 200, got: %s", node1On3.NextHop.RemoteSID())
	}

	// Connect Alice to S1 and Charlie to S3
	alice := newTestIRCClient(t, s1, "alice")
	charlie := newTestIRCClient(t, s3, "charlie")

	time.Sleep(150 * time.Millisecond)

	// Both join #multihop
	alice.SendLine("JOIN #multihop")
	charlie.SendLine("JOIN #multihop")
	time.Sleep(150 * time.Millisecond)

	// Flush lines
	for {
		if alice.ReadLineTimeout(20*time.Millisecond) == "" {
			break
		}
	}
	for {
		if charlie.ReadLineTimeout(20*time.Millisecond) == "" {
			break
		}
	}

	// Alice sends channel message on S1 -> Charlie receives on S3
	alice.SendLine("PRIVMSG #multihop :Multi-hop message from S1 to S3")
	charlieLine := charlie.ReadLineTimeout(1 * time.Second)
	if !strings.Contains(charlieLine, "PRIVMSG #multihop :Multi-hop message from S1 to S3") {
		t.Errorf("charlie on S3 did not receive multi-hop channel message from alice on S1, got: %s", charlieLine)
	}

	// Charlie sends private message to Alice (S3 -> S1)
	charlie.SendLine("PRIVMSG alice :Direct multi-hop reply")
	aliceLine := alice.ReadLineTimeout(1 * time.Second)
	if !strings.Contains(aliceLine, "PRIVMSG alice :Direct multi-hop reply") {
		t.Errorf("alice on S1 did not receive multi-hop privmsg from charlie on S3, got: %s", aliceLine)
	}
}

func TestS2SLinksCommand(t *testing.T) {
	s1 := createTestServer(t, "100", "srv1.test", nil)
	s2 := createTestServer(t, "200", "srv2.test", nil)
	s3 := createTestServer(t, "300", "srv3.test", nil)

	linkTestServers(t, s1, s2, nil, nil)
	linkTestServers(t, s2, s3, nil, nil)

	alice := newTestIRCClient(t, s1, "alice")
	time.Sleep(100 * time.Millisecond)

	// Flush registration output
	for {
		if alice.ReadLineTimeout(20*time.Millisecond) == "" {
			break
		}
	}

	alice.SendLine("LINKS")

	var links []string
	var endOfLinks bool
	for {
		line := alice.ReadLineTimeout(1 * time.Second)
		if line == "" {
			break
		}
		if strings.Contains(line, " 364 ") { // RPL_LINKS
			links = append(links, line)
		} else if strings.Contains(line, " 365 ") { // RPL_ENDOFLINKS
			endOfLinks = true
			break
		}
	}

	if !endOfLinks {
		t.Errorf("expected 365 RPL_ENDOFLINKS")
	}
	if len(links) < 3 {
		t.Errorf("expected at least 3 servers in LINKS output, got %d: %v", len(links), links)
	}
}

func TestS2SKnockAndInvite(t *testing.T) {
	s1 := createTestServer(t, "100", "srv1.test", nil)
	s2 := createTestServer(t, "200", "srv2.test", nil)

	linkTestServers(t, s1, s2, nil, nil)

	alice := newTestIRCClient(t, s1, "alice")
	bob := newTestIRCClient(t, s2, "bob")

	time.Sleep(100 * time.Millisecond)

	// Alice joins and sets +i on #secret
	alice.SendLine("JOIN #secret")
	alice.SendLine("MODE #secret +i")
	time.Sleep(100 * time.Millisecond)

	// Flush buffers
	for {
		if alice.ReadLineTimeout(20*time.Millisecond) == "" {
			break
		}
	}
	for {
		if bob.ReadLineTimeout(20*time.Millisecond) == "" {
			break
		}
	}

	// Bob knocks on #secret from server 2
	bob.SendLine("KNOCK #secret")
	bobAckLine := bob.ReadLineTimeout(1 * time.Second)
	if !strings.Contains(bobAckLine, " 710 ") {
		t.Errorf("bob did not receive 710 knock ack, got: %s", bobAckLine)
	}

	aliceKnockLine := alice.ReadLineTimeout(1 * time.Second)
	if !strings.Contains(aliceKnockLine, "is knocking on #secret") {
		t.Errorf("alice did not receive knock notice from bob, got: %s", aliceKnockLine)
	}

	// Alice invites Bob to #secret
	alice.SendLine("INVITE bob #secret")
	bobInviteLine := bob.ReadLineTimeout(1 * time.Second)
	if !strings.Contains(bobInviteLine, "INVITE") || !strings.Contains(bobInviteLine, "#secret") {
		t.Errorf("bob did not receive invite from alice, got: %s", bobInviteLine)
	}

	// Bob can now join #secret
	bob.SendLine("JOIN #secret")
	time.Sleep(100 * time.Millisecond)

	ch2 := s2.channels.Get("#secret")
	if ch2 == nil || !ch2.hasClient(s2.clients.Get("bob")) {
		t.Errorf("bob failed to join #secret after invite")
	}
}

func TestS2SWallops(t *testing.T) {
	s1 := createTestServer(t, "100", "srv1.test", nil)
	s2 := createTestServer(t, "200", "srv2.test", nil)

	linkTestServers(t, s1, s2, nil, nil)

	alice := newTestIRCClient(t, s1, "alice")
	bob := newTestIRCClient(t, s2, "bob")

	time.Sleep(100 * time.Millisecond)

	// Bob enables mode +w (wallops) on server 2
	bob.SendLine("MODE bob +w")
	time.Sleep(50 * time.Millisecond)

	// Flush buffers
	for {
		if alice.ReadLineTimeout(20*time.Millisecond) == "" {
			break
		}
	}
	for {
		if bob.ReadLineTimeout(20*time.Millisecond) == "" {
			break
		}
	}

	// Alice sends WALLOPS from server 1
	alice.SendLine("WALLOPS :System maintenance in 10 minutes")
	bobWallopsLine := bob.ReadLineTimeout(1 * time.Second)
	if !strings.Contains(bobWallopsLine, "WALLOPS") || !strings.Contains(bobWallopsLine, "System maintenance in 10 minutes") {
		t.Errorf("bob did not receive WALLOPS message from alice, got: %s", bobWallopsLine)
	}
}

func TestS2SEncap(t *testing.T) {
	s1 := createTestServer(t, "100", "srv1.test", nil)
	s2 := createTestServer(t, "200", "srv2.test", nil)

	_, link2 := linkTestServers(t, s1, s2, nil, nil)

	alice := newTestIRCClient(t, s1, "alice")
	_ = alice
	time.Sleep(100 * time.Millisecond)

	aliceClient := s1.clients.Get("alice")
	if aliceClient == nil {
		t.Fatalf("alice not found on server 1")
	}
	aliceUID := aliceClient.UID()

	// 1. Test ENCAP * CHGHOST
	link2.SendLine(fmt.Sprintf("ENCAP * CHGHOST %s user.spoof.net", aliceUID))
	time.Sleep(100 * time.Millisecond)
	if aliceClient.Hostname() != "user.spoof.net" {
		t.Errorf("expected updated hostname 'user.spoof.net', got: %s", aliceClient.Hostname())
	}

	// 2. Test ENCAP * SU (account login)
	link2.SendLine(fmt.Sprintf("ENCAP * SU %s AliceAccount", aliceUID))
	time.Sleep(100 * time.Millisecond)
	if aliceClient.AccountName() != "AliceAccount" {
		t.Errorf("expected account 'AliceAccount', got: %s", aliceClient.AccountName())
	}

	// 3. Test ENCAP * RSFNC (forced nick change)
	newTS := time.Now().Unix()
	link2.SendLine(fmt.Sprintf("ENCAP * RSFNC %s alice_renamed %d %d", aliceUID, newTS, newTS))
	time.Sleep(100 * time.Millisecond)
	if aliceClient.Nick() != "alice_renamed" {
		t.Errorf("expected renamed nick 'alice_renamed', got: %s", aliceClient.Nick())
	}
}

func TestS2SSave(t *testing.T) {
	s1 := createTestServer(t, "100", "srv1.test", nil)
	s2 := createTestServer(t, "200", "srv2.test", nil)

	_, link2 := linkTestServers(t, s1, s2, nil, nil)

	alice := newTestIRCClient(t, s1, "alice")
	_ = alice
	time.Sleep(100 * time.Millisecond)

	aliceClient := s1.clients.Get("alice")
	if aliceClient == nil {
		t.Fatalf("alice not found on server 1")
	}
	aliceUID := aliceClient.UID()

	// Server 2 sends SAVE command targeting Alice's UID
	link2.SendLine(fmt.Sprintf("SAVE %s %d", aliceUID, time.Now().Unix()))
	time.Sleep(100 * time.Millisecond)

	// Alice's nick should now be changed to her UID
	if aliceClient.Nick() != aliceUID {
		t.Errorf("expected nick to be saved to UID %s, got: %s", aliceUID, aliceClient.Nick())
	}
	if s1.clients.Get("alice") != nil {
		t.Errorf("old nick 'alice' should no longer be in server 1 lookup set")
	}
	if s1.clients.Get(aliceUID) != aliceClient {
		t.Errorf("client not found by new nick (UID) in lookup set")
	}
}

func TestS2SBMaskBurst(t *testing.T) {
	s1 := createTestServer(t, "100", "srv1.test", nil)

	alice := newTestIRCClient(t, s1, "alice")
	time.Sleep(50 * time.Millisecond)

	alice.SendLine("JOIN #bmask_chan")
	time.Sleep(50 * time.Millisecond)

	// Alice sets ban mask and invite mask
	alice.SendLine("MODE #bmask_chan +b *!*@evil.com")
	alice.SendLine("MODE #bmask_chan +I *!*@trusted.org")
	time.Sleep(100 * time.Millisecond)

	ch1 := s1.channels.Get("#bmask_chan")
	if ch1 == nil {
		t.Fatalf("channel #bmask_chan not found on s1")
	}

	// Now start server 2 and link them
	s2 := createTestServer(t, "200", "srv2.test", nil)
	linkTestServers(t, s1, s2, nil, nil)

	time.Sleep(150 * time.Millisecond)

	// S2 should have received #bmask_chan with the ban and invite masks in the burst
	ch2 := s2.channels.Get("#bmask_chan")
	if ch2 == nil {
		t.Fatalf("channel #bmask_chan not found on s2 after burst")
	}

	ch2.stateMutex.RLock()
	hasBan := ch2.lists[modes.BanMask].Match("spammer!bot@evil.com")
	hasInvite := ch2.lists[modes.InviteMask].Match("friend!user@trusted.org")
	ch2.stateMutex.RUnlock()

	if !hasBan {
		t.Errorf("ban mask *!*@evil.com was not properly synced via BMASK burst to server 2")
	}
	if !hasInvite {
		t.Errorf("invite mask *!*@trusted.org was not properly synced via BMASK burst to server 2")
	}
}
