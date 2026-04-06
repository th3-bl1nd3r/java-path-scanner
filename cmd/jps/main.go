package main

import (
	"github.com/th3-bl1nd3r/java-path-scanner/runner"
)

func main() {
	runner.ShowBanner()
	options := runner.ParseOptions()
	r, err := runner.New(options)
	if err != nil {
		panic(err)
	}
	defer r.Close()
	r.RunEnumeration()
}
