package main

import "os"

func helper() {
	os.Exit(2) // допустимо: вызов не в функции main
}

func main() {
	helper()
	os.Exit(1) // want "прямой вызов os.Exit в функции main запрещен"
}
