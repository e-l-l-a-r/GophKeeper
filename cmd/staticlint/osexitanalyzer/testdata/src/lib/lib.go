package lib

import "os"

// Stop завершает процесс; в пакете, отличном от main, анализатор молчит.
func Stop() {
	os.Exit(1)
}
