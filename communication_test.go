package proxyproxy_test

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"testing"

	"github.com/Neothorn23/proxyproxy"
)

const (
	testDomain        = "testdomain"
	httpsTestUrl      = "https://" + testDomain + ":443"
	ntlmAuthMethod    = "NTLM"
	proxyResponseBody = "NTLM Authentication is required"
	testNegotiate     = "TestNegotiate"
	testChallenge     = "TestChallenge"
	testContent       = "TestContent"
)

type dummyAuthHandler struct {
}

type dummySecurityContext struct {
}

type dummyProxyEventListener struct {
}

func (h *dummyAuthHandler) GetContext() (proxyproxy.SecurityContext, error) {

	return &dummySecurityContext{}, nil

}

func (h *dummyAuthHandler) Close() error {
	return nil
}

func (c *dummySecurityContext) GetNegotiate() []byte {
	return []byte(testNegotiate)
}

func (c *dummySecurityContext) GetAuthenticateFromChallenge(challenge []byte) ([]byte, error) {
	if bytes.Equal(challenge, []byte(testChallenge)) {
		return []byte("TestAuth"), nil
	} else {
		return nil, fmt.Errorf("Unexpected challenge: %s", challenge)
	}
}

func (c *dummySecurityContext) Close() error {
	return nil
}

func (l *dummyProxyEventListener) OnProxyEvent(event *proxyproxy.ProxyEvent) {
	fmt.Printf("%s: %v\n", proxyproxy.EventText(event.EventType), event)
}

func TestProxyWithHttps(t *testing.T) {
	clientServerConn, clientClientConn := net.Pipe()
	proxyServerConn, proxyClientConn := net.Pipe()

	go runDummyClient(clientClientConn, t)
	go runDummyProxy(proxyServerConn, t)

	communication, error := proxyproxy.NewProxyCommunication(clientServerConn, proxyClientConn, &dummyAuthHandler{}, &dummyProxyEventListener{})
	if error != nil {
		t.Error(error)
		return
	}

	error = communication.HandleConnection()
	if error != nil {
		t.Error(error)
		return
	}

}

func runDummyClient(conn net.Conn, t *testing.T) {
	defer conn.Close()

	request := `CONNECT testdomain:443 HTTP/1.1
User-Agent: Go Test Environment
Proxy-Connection: keep-alive
Connection: keep-alive
Host: testdomain:443

`

	fmt.Printf("Sending request:\n%s\n", request)
	io.WriteString(conn, request)

	clientReader := bufio.NewReader(conn)
	response, err := http.ReadResponse(clientReader, nil)
	if err != nil {
		t.Error(err)
		return
	}

	if response.StatusCode != http.StatusOK {
		t.Errorf("Unexpected status code. Expected %q but got %q", http.StatusOK, response.StatusCode)
		return
	}

	responseBody, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Error(err)
		return
	}

	recievedContent := string(responseBody)
	if recievedContent != testContent {
		t.Errorf("Expected content %q but got %q", testContent, recievedContent)
	}

}

func runDummyProxy(conn net.Conn, t *testing.T) {
	defer conn.Close()

	proxyReader := bufio.NewReader(conn)
	initialRequest, err := http.ReadRequest(proxyReader)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("Recieved first request: %s %s\n", initialRequest.Method, initialRequest.RequestURI)

	requireAuthResponse :=
		`HTTP/1.1 407 authenticationrequired
Content-Type: text/plain
Cache-Control: no-cache
Content-Length: 12
Proxy-Connection: Keep-Alive
Proxy-Authenticate: NTLM

authrequired`

	io.WriteString(conn, requireAuthResponse)

	negotiateRequest, err := http.ReadRequest(proxyReader)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("Recieved negotiate request: %s %s\n", negotiateRequest.Method, negotiateRequest.RequestURI)
	expectedNegotiateToken := ntlmAuthMethod + " " + base64.StdEncoding.EncodeToString([]byte(testNegotiate))
	recievedNegotiateToken := negotiateRequest.Header.Get("Proxy-Authorization")

	if expectedNegotiateToken != recievedNegotiateToken {
		t.Errorf("Expected negotiate token %q but got %q\n", expectedNegotiateToken, recievedNegotiateToken)
		return
	}

	challengeResponse := fmt.Sprintf(`HTTP/1.1 407 authenticationrequired
Content-Type: text/plain
Cache-Control: no-cache
Content-Length: 12
Proxy-Connection: Keep-Alive
Proxy-Authenticate: NTLM %s

authrequired`, base64.StdEncoding.EncodeToString([]byte(testChallenge)))

	io.WriteString(conn, challengeResponse)

	authRequest, err := http.ReadRequest(proxyReader)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("Recieved auth request: %s %s\n", authRequest.Method, authRequest.RequestURI)
	expectedAuthToken := ntlmAuthMethod + " " + base64.StdEncoding.EncodeToString([]byte(testNegotiate))
	recievedAuthToken := negotiateRequest.Header.Get("Proxy-Authorization")

	if expectedAuthToken != recievedAuthToken {
		t.Errorf("Expected auth token %q but got %q\n", expectedAuthToken, recievedAuthToken)
		return
	}

	finalResponse := fmt.Sprintf(`HTTP/1.0 200 Connection established
Content-Type: text/plain
Cache-Control: no-cache
Content-Length: %d
Proxy-Connection: Keep-Alive

%s`, len(testContent), testContent)
	io.WriteString(conn, finalResponse)

}
