//go:build !(openbsd && (amd64 || arm64))

package audit

// NewSyslog is only implemented on OpenBSD amd64 and arm64.
func NewSyslog(tag string) (Logger, error) { return nil, ErrUnsupported }
