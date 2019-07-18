package sspi

import (
	"github.com/Neothorn23/proxyproxy"
	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/ntlm"
	"github.com/pkg/errors"
)

type sspiAuthHandler struct {
	userCredentials *sspi.Credentials
}

type sspiSecurityContext struct {
	negotiate   []byte
	ntlmContext *ntlm.ClientContext
}

func (h *sspiAuthHandler) GetContext() (proxyproxy.SecurityContext, error) {

	secctx, negotiate, err := ntlm.NewClientContext(h.userCredentials)
	if err != nil {
		return nil, errors.Wrap(err, "failed to aquire security context")
	}

	return &sspiSecurityContext{
		negotiate:   negotiate,
		ntlmContext: secctx,
	}, nil

}

func (h *sspiAuthHandler) Close() error {
	return h.userCredentials.Release()
}

func (c *sspiSecurityContext) GetNegotiate() []byte {
	return c.negotiate
}

func (c *sspiSecurityContext) GetAuthenticateFromChallenge(challenge []byte) ([]byte, error) {
	authenticate, err := c.ntlmContext.Update(challenge)
	if err != nil {
		return nil, errors.Wrap(err, "failed to retrieve authenticate")
	}

	return authenticate, nil
}

func (c *sspiSecurityContext) Close() error {
	return c.ntlmContext.Release()
}

/*
NewSSPIAuthHandler creates a new NTLMAuthHandler whiches uses Windows SSPI API
*/
func NewSSPIAuthHandler() (proxyproxy.NtlmAuhtHandler, error) {
	cred, err := ntlm.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, errors.Wrap(err, "Can not aquire user credentials!")
	}

	return &sspiAuthHandler{
		userCredentials: cred,
	}, nil
}
