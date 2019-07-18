package proxyproxy

/*
NtlmAuhtHandler - Interface for implementations which handle NTLM authentication
*/
type NtlmAuhtHandler interface {
	GetContext() (SecurityContext, error)
	Close() error
}

/*
SecurityContext - Interface for accessing security context for authentication1
*/
type SecurityContext interface {
	GetNegotiate() []byte
	GetAuthenticateFromChallenge(challange []byte) ([]byte, error)
	Close() error
}