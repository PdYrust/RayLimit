//go:build !unix

package privilege

func getEUID() int {
	return -1
}
