//go:build !linux

package textdelta

import "errors"

func runtimeClock() (clockSample, error) {
	return clockSample{}, errors.New("textdelta: reference transport supports Linux only")
}
