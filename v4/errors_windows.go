package mux

import (
	"errors"
	"io"
	"syscall"
)

// isConnCloseError returns true if the error is from the peer closing the
// connection early.
func isConnCloseError(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.Errno(10041)) || // WSAEPROTOTYPE
		errors.Is(err, syscall.WSAECONNABORTED) ||
		errors.Is(err, syscall.WSAECONNRESET)
}
