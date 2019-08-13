package proxyproxy

import (
	"net"
)

//ProxyEventType ist used to represent the type of an event
type ProxyEventType int

//EventSeverity  defines an event's severity
type EventSeverity int

//Defined event types
const (
	EventCreatingConnection ProxyEventType = iota
	EventProcessingRequest
	EventNtlmAuthRequestDetected
	EventRecievedAuthToken
	EventSendingAuthToken
	EventSendingRequest
	EventPeekedResponse
	EventRecievedResponse
	EventConnectionEstablished
	EventConnectionClosed
)

//Defined severity levels
const (
	TraceEvent EventSeverity = iota
	DebugEvent
	InfoEvent
	WarnEvent
	ErrorEvent
	FatalEvent
)

var eventText = map[ProxyEventType]string{
	EventCreatingConnection:      "Creating connection",
	EventProcessingRequest:       "Processing request",
	EventNtlmAuthRequestDetected: "NTLM authentication request detected",
	EventRecievedAuthToken:       "Recieved authentication token",
	EventSendingAuthToken:        "Sending authentication token",
	EventSendingRequest:          "Sending request to proxy server",
	EventPeekedResponse:          "Peeking response from proxy server",
	EventRecievedResponse:        "Recieved response from proxy server",
	EventConnectionEstablished:   "Connection with to proxy server ist established",
	EventConnectionClosed:        "Connection ist closed",
}

//A ProxyEventListener will be notified in the case of an event
type ProxyEventListener interface {
	OnProxyEvent(event *ProxyEvent)
}

//ProxyEvent contains data for an event emittet by proxyproxy
type ProxyEvent struct {
	EventType     ProxyEventType
	ClientHost    net.Addr
	ProxyHost     net.Addr
	Method        string
	RequestURI    string
	Communication *ProxyCommunication
}

//EventText returns text for event type
func EventText(t ProxyEventType) string {
	return eventText[t]
}

func newProxyEvent(t ProxyEventType, s EventSeverity, com *ProxyCommunication) *ProxyEvent {

	event := &ProxyEvent{
		EventType:     t,
		ClientHost:    com.GetClientAddr(),
		ProxyHost:     com.GetProxyServerAddr(),
		Communication: com,
	}

	request := com.GetCurrentRequest()
	if request != nil {
		event.Method = request.Method
		event.RequestURI = request.RequestURI
	}

	return event
}
