package pgp

import (
	"fmt"
	"os"
)

func GetFileContents(path string) string {
	contents, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintln("error reading file: ", err)
	}

	return string(contents)
}
