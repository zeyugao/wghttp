package goshadow

import (
	"fmt"
	"log"
	"os"
)

var logger = log.New(os.Stderr, "", log.Lshortfile|log.LstdFlags)

func logf(f string, v ...interface{}) {
	if Verbose {
		logger.Output(2, fmt.Sprintf(f, v...))
	}
}
