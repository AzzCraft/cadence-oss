//go:build !unix

package evidence

import "os"

func openArtifact(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}
