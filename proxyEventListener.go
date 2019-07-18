package proxyproxy

//ProxyEventType ist used to represent the type of an event
type ProxyEventType int

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

var eventText = map[ProxyEventType]string{
	EventCreatingConnection:		"Creating connection",
	EventProcessingRequest:			"Processing request",
	EventNtlmAuthRequestDetected: 	"NTLM authentication request detected",
	EventRecievedAuthToken:			"Recieved authentication token",
	EventSendingAuthToken: 			"Sending authentication token",
	EventSendingRequest: 			"Sending request to proxy server",
	EventPeekedResponse: 			"Peeking response from proxy server",
	EventRecievedResponse: 			"Recieved response from proxy server",
	EventConnectionEstablished:		"Connection with to proxy server ist established",
	EventConnectionClosed:			"Connection ist closed",
}

//A ProxyEventListener will be notified in the case of an event
type ProxyEventListener interface {
	OnProxyEvent(t ProxyEventType, pc *ProxyCommunication)
}

//EventText returns text for event type
func EventText(t ProxyEventType) string {
	return eventText[t]
}