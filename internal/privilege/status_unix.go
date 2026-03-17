//go:build unix

package privilege

import "os"

func getEUID() int {
	return os.Geteuid()
}
