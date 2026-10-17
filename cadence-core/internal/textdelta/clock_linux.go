package textdelta

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func runtimeClock() (clockSample, error) {
	var ticks syscall.Timespec
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 7, uintptr(unsafe.Pointer(&ticks)), 0) // CLOCK_BOOTTIME includes suspend.
	if errno != 0 {
		return clockSample{}, errors.New("textdelta: CLOCK_BOOTTIME unavailable")
	}
	instance, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return clockSample{}, errors.New("textdelta: boot identity unavailable")
	}
	return clockSample{instance: strings.TrimSpace(string(instance)), ticks: time.Duration(ticks.Sec)*time.Second + time.Duration(ticks.Nsec)}, nil
}
