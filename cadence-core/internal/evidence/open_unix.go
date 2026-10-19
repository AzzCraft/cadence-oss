//go:build unix

package evidence

import (
	"os"
	"syscall"
)

func openArtifact(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
