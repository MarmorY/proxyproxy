package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"encoding/base64"
	"io/ioutil"
	"net/http"

	"github.com/alexbrainman/sspi/ntlm"
	"github.com/sirupsen/logrus"
)

const (
	ntlmAuthMethod  = "NTLM"
	proxyBufferSize = 4096
)

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
	logger             *logrus.Entry
}

var (
	connectionCount = 0
)

func handleConnection(clientConn net.Conn, proxyAddress string) {

	communication, err := NewProxyCommunication(clientConn, proxyAddress)

	if err != nil {
		logrus.Infof("Error initializig communication: %v", err)
		return
	}

	logger := communication.logger

	//Check if authentication is nessesary
	if communication.isNtlmAuhtenticationRequired() {

		//Phase 1: NTLM Authentication requeseted
		//Aquire credentials for current user
		logger.Debug("NTLM Authentication request detected")
		cred, err := ntlm.AcquireCurrentUserCredentials()
		if err != nil {
			logger.Infof("Cannot aquire current user credentials: %v", err)
			return
		}
		defer cred.Release()

		//Retrieve Security Context
		secctx, negotiate, err := ntlm.NewClientContext(cred)
		if err != nil {
			logger.Infof("Cannot retrieve security context: %v", err)
			return
		}

		if err := communication.sendRequestWithAuthHeader(negotiate); err != nil {
			logger.Infof("Error sending auth phase 1: %v", err)
			return
		}

		if communication.isExpectedResponseCode() {
			// Phase 2: Challange token
			ntlmChallengeHeader := communication.getNTLMToken()

			challengeString := strings.Replace(ntlmChallengeHeader, ntlmAuthMethod+" ", "", -1)
			challengeBytes, _ := base64.StdEncoding.DecodeString(challengeString)
			authenticate, err := secctx.Update(challengeBytes)
			if err != nil {
				logger.Infof("Error challanging token: %v\n", err)
				return
			}

			if err := communication.sendRequestWithAuthHeader(authenticate); err != nil {
				logger.Infof("Error sending auth phase 2: %v", err)
				return
			}

		}

	}

	communication.handleRemainingCommunication()

}

func NewProxyCommunication(clientConn net.Conn, proxyAddress string) (*ProxyCommunication, error) {

	connectionCount++
	connId := connectionCount

	logger := logrus.WithFields(logrus.Fields{"Id": connId, "client": clientConn.RemoteAddr()})

	logger.Info("Creating new proxy connection")

	proxyConn, err := net.DialTimeout("tcp", proxyAddress, 10*time.Second)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error opening connection to proxy: %v", err))
	}

	result := &ProxyCommunication{
		proxyConnection:  proxyConn,
		clientConnection: clientConn,
		logger:           logger,
	}

	result.clientReader = bufio.NewReader(clientConn)
	result.proxyReader = bufio.NewReaderSize(proxyConn, proxyBufferSize)

	//Parse client's request
	if err := result.parseCurrentRequest(); err != nil {
		return nil, err
	}
	logger.Infof("Processing request %v %v\n", result.currentRequest.Method, result.currentRequest.RequestURI)

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
		return nil, errors.New(fmt.Sprintf("Error retrieving initial response from proxy: %v", err))
	}

	return result, nil

}

func (pc *ProxyCommunication) getNTLMToken() string {
	value := pc.currentResponse.Header.Get(pc.responseHeader)
	pc.logger.WithFields(logrus.Fields{"token": value}).Debug("Recieved auth token")
	return value
}

func (pc *ProxyCommunication) parseCurrentRequest() error {
	//Parse client request
	request, err := http.ReadRequest(pc.clientReader)
	if err != nil {
		return errors.New(fmt.Sprintf("Error parsing request: %v", err))
	} else {
		pc.currentRequest = request
	}

	return nil
}

func (pc *ProxyCommunication) isNtlmAuhtenticationRequired() bool {
	return pc.isExpectedResponseCode() &&
		pc.getNTLMToken() == ntlmAuthMethod
}

func (pc *ProxyCommunication) isExpectedResponseCode() bool {
	return pc.currentResponse.StatusCode == pc.expectedStatusCode
}

func (pc *ProxyCommunication) sendRequestWithAuthHeader(authPayload []byte) error {
	token := ntlmAuthMethod + " " + base64.StdEncoding.EncodeToString(authPayload)
	pc.logger.WithFields(logrus.Fields{"token": token}).Debug("Sending Token")
	pc.currentRequest.Header.Set(pc.requestHeader, token)
	return pc.sendRequest()
}

func (pc *ProxyCommunication) sendRequest() error {
	pc.logger.Debug("Sending Request")
	pc.currentRequest.Write(pc.proxyConnection)

	if err := pc.peekResponse(); err != nil {
		return errors.New(fmt.Sprintf("Error peeking response after sending request: %v", err))
	}

	if err := pc.retrieveResponse(); err != nil {
		return errors.New(fmt.Sprintf("Error retrieving response after sending request: %v", err))
	}
	pc.logger.Debugf("Recieved Response with Status: %v", pc.currentResponse.StatusCode)

	return nil
}

func (pc *ProxyCommunication) peekResponse() error {

	//Read byte and unread it to trigger filling the buffer
	if _, err := pc.proxyReader.ReadByte(); err != nil {
		return err
	}
	if err := pc.proxyReader.UnreadByte(); err != nil {
		return err
	}

	peekSize := pc.proxyReader.Buffered()
	pc.logger.Debugf("Buffered bytes: %v", peekSize)
	buf, err := pc.proxyReader.Peek(peekSize)
	if err != nil {
		pc.logger.Debugf("Peek result: %v", err)
	}
	pc.logger.Debugf("Peeked %v bytes", len(buf))

	peekReader := bufio.NewReader(bytes.NewReader(buf))

	response, err := http.ReadResponse(peekReader, pc.currentRequest)
	if err != nil {
		return errors.New(fmt.Sprintf("Error parsing http response: %v", err))
	}
	response.Body.Close()
	pc.logger.WithFields(logrus.Fields{"status": response.StatusCode}).Debug("Peeked status")

	return nil
}

func (pc *ProxyCommunication) retrieveResponse() error {
	pc.logger.Debug("Retrieving repsonse")
	response, err := http.ReadResponse(pc.proxyReader, pc.currentRequest)
	if err != nil {
		return errors.New(fmt.Sprintf("Error parsing http response: %v", err))
	}

	//Read response body into buffer and add this to response
	if response.ContentLength > 0 {
		bodyBuff, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return errors.New(fmt.Sprintf("Error while reading response body: %v", err))
		}
		response.Body.Close()
		response.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBuff))
	} else {
		response.Body.Close()
		response.Body = nil
	}

	pc.currentResponse = response

	return nil
}

func (pc *ProxyCommunication) handleRemainingCommunication() error {
	if err := pc.currentResponse.Write(pc.clientConnection); err != nil {
		return errors.New(fmt.Sprintf("Error sending last parsed response to client: %v", err))
	}

	//Handle data transfer until connection is no more needed
	var wg sync.WaitGroup
	wg.Add(1)
	go transfer(pc.proxyConnection, pc.clientReader, &wg)
	wg.Add(1)
	go transfer(pc.clientConnection, pc.proxyReader, &wg)
	wg.Wait()
	pc.logger.Info("Closing proxy connection")
	pc.clientConnection.Close()
	pc.proxyConnection.Close()

	return nil
}

func transfer(destination io.Writer, source io.Reader, wg *sync.WaitGroup) {
	defer wg.Done()
	io.Copy(destination, source)
}

func prepareRequest(request *http.Request) {
	request.Header.Set("Proxy-Connection", "keep-alive")
	request.Header.Set("Connection", "keep-alive")
}

func main() {

	//Confugure Logging
	logrus.SetFormatter(&logrus.TextFormatter{
		ForceColors:   true,
		FullTimestamp: false,
	})

	//Define CLI flags
	destinationProxy := flag.String("proxy", "", "destination proxy: <ip addr>:<port>")
	listenAddress := flag.String("listen", "127.0.0.1:3128", "adress to list on: [ip addr]:<port>")
	debug := flag.Bool("v", false, "Verbose output")

	flag.Parse()

	if *destinationProxy == "" {
		fmt.Println("Parameter \"proxy\" is not set.")
		flag.PrintDefaults()
		return
	}

	if *listenAddress == "" {
		fmt.Println("Parameter \"listen\" is not set.")
		flag.PrintDefaults()
		return
	}

	if *debug {
		logrus.SetLevel(logrus.DebugLevel)
		logrus.Debug("Verbos output is enabled.")
	}

	logrus.Infof("Listening on %v", *listenAddress)
	logrus.Infof("Connection to %v", *destinationProxy)

	ln, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		logrus.Fatalf("Error: %v", err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			logrus.Fatalf("Error: %v", err)
		}
		go handleConnection(conn, *destinationProxy)
	}

	http.Get("http://test")
}
