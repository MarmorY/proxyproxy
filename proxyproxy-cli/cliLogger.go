package main

import (
	"github.com/apex/log"
	"github.com/Neothorn23/proxyproxy"
)

type cliLogger struct {
	logger *log.Entry
}

func (l *cliLogger) OnProxyEvent(t proxyproxy.ProxyEventType, pc *proxyproxy.ProxyCommunication) {
	if t == proxyproxy.EventCreatingConnection {
		l.logger = l.logger.WithFields(log.Fields{"Id": pc.GetID()})
	}
	l.logger.Info(proxyproxy.EventText(t))
}

//NewCliLogger creates a new cli logger wich implements ProxyEventListener
func NewCliLogger(logger *log.Entry) proxyproxy.ProxyEventListener {
	return &cliLogger{
		logger: logger,
	}
}