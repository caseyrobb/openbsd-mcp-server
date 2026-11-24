//go:build !openbsd

package sandbox

// Apply is unavailable off OpenBSD. The caller decides whether to refuse to
// start (default) or continue for local development (-unsafe-dev).
func Apply(Policy) ([]string, error) { return nil, ErrUnsupported }
