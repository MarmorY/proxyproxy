package proxyproxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"encoding/base64"
	"io/ioutil"
	"net/http"
)

const (
	ntlmAuthMethod  = "NTLM"
	proxyBufferSize = 4096
)

/*
ProxyCommunication contains all data for a proxy communication
*/
type ProxyCommunication struct {
	isTunnel           bool
	responseHeader     string
	requestHeader      string
	expectedStatusCode int
	clientConnection   net.Conn
	clientReader       *bufio.Reader
	proxyConnection    net.Conn
	proxyReader        *bufio.Reader
	currentRequest     *http.Request
	currentResponse    *http.Response
	peekedResponse     *http.Response
	eventListener      ProxyEventListener
	proxyAddress       string
	authHandler        NtlmAuhtHandler
	id                 int
}

var (
	connectionCount = 0
)

/*
NewProxyCommunication creates a new ProxyCommunication
*/
func NewProxyCommunication(clientConn net.Conn, proxyConn net.Conn, authHandler NtlmAuhtHandler, eventListener ProxyEventListener) (*ProxyCommunication, error) {
	connectionCount++

	result := &ProxyCommunication{
		proxyConnection:  proxyConn,
		clientConnection: clientConn,
		eventListener:    eventListener,
		authHandler:      authHandler,
		id:               connectionCount,
	}

	eventListener.OnProxyEvent(EventCreatingConnection, result)

	result.clientReader = bufio.NewReader(clientConn)
	result.proxyReader = bufio.NewReaderSize(proxyConn, proxyBufferSize)

	//Parse client's request
	if err := result.parseCurrentRequest(); err != nil {
		return nil, err
	}

	eventListener.OnProxyEvent(EventProcessingRequest, result)

	//logger.Infof("Processing request %v %v", result.currentRequest.Method, result.currentRequest.RequestURI)

	result.isTunnel = result.currentRequest.Method == http.MethodConnect
	if result.isTunnel {
		result.responseHeader = "Proxy-Authenticate"
		result.requestHeader = "Proxy-Authorization"
		result.expectedStatusCode = 407
	} else {
		result.responseHeader = "Www-Authenticate"
		result.requestHeader = "Authorization"
		result.expectedStatusCode = 401

	}

	//Send request to ProxyCommunication
	prepareRequest(result.currentRequest)

	if err := result.sendRequest(); err != nil {
		return nil, fmt.Errorf("Error retrieving initial response from proxy: %v", err)
	}

	return result, nil

}

/*
HandleConnection handels Connection to proxy server
*/
func (pc *ProxyCommunication) HandleConnection() error {

	defer closeConnections(pc)

	//Check if authentication is nessesary
	if pc.isNtlmAuhtenticationRequired() {
		if err := pc.retrieveResponse(); err != nil {
			return fmt.Errorf("Failed to read response: %v", err)
		}

		//Phase 1: NTLM Authentication requeseted
		//logger.Debug("NTLM Authentication request detected")
		pc.eventListener.OnProxyEvent(EventNtlmAuthRequestDetected, pc)

		//Retrieve Security Context
		secctx, err := pc.authHandler.GetContext()
		if err != nil {
			return fmt.Errorf("Cannot retrieve security context: %v", err)
		}

		if err := pc.sendRequestWithAuthHeader(secctx.GetNegotiate()); err != nil {
			return fmt.Errorf("Error sending auth phase 1: %v", err)
		}

		if pc.isExpectedResponseCode() {
			if err := pc.retrieveResponse(); err != nil {
				return fmt.Errorf("Failed to read response: %v", err)
			}

			// Phase 2: Challange token
			ntlmChallengeHeader := pc.getNTLMToken()

			challengeString := strings.Replace(ntlmChallengeHeader, ntlmAuthMethod+" ", "", -1)
			challengeBytes, _ := base64.StdEncoding.DecodeString(challengeString)
			authenticate, err := secctx.GetAuthenticateFromChallenge(challengeBytes)
			if err != nil {
				return fmt.Errorf("Error challanging token: %v", err)
			}

			if err := pc.sendRequestWithAuthHeader(authenticate); err != nil {
				return fmt.Errorf("Error sending auth phase 2: %v", err)
			}

		}

	}

	pc.handleRemainingCommunication()

	return nil
}

//GetID returns the communication's id
func (pc *ProxyCommunication) GetID() int {
	return pc.id
}

//GetClientAddr returns the address of the original client
func (pc *ProxyCommunication) GetClientAddr() net.Addr {
	return pc.clientConnection.RemoteAddr()
}

//GetProxyServerAddr returns the address of the original proxy server
func (pc *ProxyCommunication) GetProxyServerAddr() net.Addr {
	return pc.proxyConnection.RemoteAddr()
}

//GetCurrentRequest return currently processed request
func (pc *ProxyCommunication) GetCurrentRequest() *http.Request {
	return pc.currentRequest
}

func (pc *ProxyCommunication) getNTLMToken() string {
	value := pc.peekedResponse.Header.Get(pc.responseHeader)
	//pc.logger.WithFields(log.Fields{"token": value}).Debug("Recieved auth token")
	pc.eventListener.OnProxyEvent(EventRecievedAuthToken, pc)
	return value
}

func (pc *ProxyCommunication) parseCurrentRequest() error {
	//Parse client request
	request, err := http.ReadRequest(pc.clientReader)
	if err != nil {
		return fmt.Errorf("Error parsing request: %v", err)
	}

	pc.currentRequest = request

	return nil
}

func (pc *ProxyCommunication) isNtlmAuhtenticationRequired() bool {
	return pc.isExpectedResponseCode() &&
		pc.getNTLMToken() == ntlmAuthMethod
}

func (pc *ProxyCommunication) isExpectedResponseCode() bool {
	return pc.peekedResponse.StatusCode == pc.expectedStatusCode
}

func (pc *ProxyCommunication) sendRequestWithAuthHeader(authPayload []byte) error {
	token := ntlmAuthMethod + " " + base64.StdEncoding.EncodeToString(authPayload)
	//pc.logger.WithFields(log.Fields{"token": token}).Debug("Sending Token")
	pc.eventListener.OnProxyEvent(EventSendingAuthToken, pc)
	pc.currentRequest.Header.Set(pc.requestHeader, token)
	return pc.sendRequest()
}

func (pc *ProxyCommunication) sendRequest() error {
	//pc.logger.Debug("Sending Request")
	pc.eventListener.OnProxyEvent(EventSendingRequest, pc)
	pc.currentRequest.Write(pc.proxyConnection)

	if err := pc.peekResponse(); err != nil {
		return fmt.Errorf("Error peeking response after sending request: %v", err)
	}

	return nil
}

func (pc *ProxyCommunication) peekResponse() error {

	//Peek 1 byte to trigger buffered reader to fill it's buffer
	//if it isn't already filled
	pc.proxyReader.Peek(1)

	//Peek buffered data from TCP stream
	peekSize := pc.proxyReader.Buffered()
	buf, _ := pc.proxyReader.Peek(peekSize)

	peekReader := bufio.NewReader(bytes.NewReader(buf))

	response, err := http.ReadResponse(peekReader, pc.currentRequest)
	if err != nil {
		return fmt.Errorf("Error parsing http response: %v", err)
	}
	response.Body.Close()

	pc.peekedResponse = response
	pc.eventListener.OnProxyEvent(EventPeekedResponse, pc)
	return nil
}

func (pc *ProxyCommunication) retrieveResponse() error {
	response, err := http.ReadResponse(pc.proxyReader, pc.currentRequest)
	if err != nil {
		return fmt.Errorf("Error parsing http response: %v", err)
	}

	//Read response body into buffer and add this to response
	if response.ContentLength > 0 {
		bodyBuff, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return fmt.Errorf("Error while reading response body: %v", err)
		}
		response.Body.Close()
		response.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBuff))
	} else {
		response.Body.Close()
		response.Body = nil
	}

	pc.currentResponse = response
	pc.eventListener.OnProxyEvent(EventRecievedResponse, pc)
	return nil
}

func (pc *ProxyCommunication) handleRemainingCommunication() error {

	//Handle data transfer until connection is no more needed
	var wg sync.WaitGroup
	wg.Add(1)
	go transfer(pc.proxyConnection, pc.clientReader, &wg)
	wg.Add(1)
	go transfer(pc.clientConnection, pc.proxyReader, &wg)
	wg.Wait()

	return nil
}

func closeConnections(pc *ProxyCommunication) {
	pc.proxyConnection.Close()
	pc.clientConnection.Close()
	pc.eventListener.OnProxyEvent(EventConnectionClosed, pc)
}

func transfer(destination io.Writer, source io.Reader, wg *sync.WaitGroup) {
	defer wg.Done()
	io.Copy(destination, source)
}

func prepareRequest(request *http.Request) {
	request.Header.Set("Proxy-Connection", "keep-alive")
	request.Header.Set("Connection", "keep-alive")
}
