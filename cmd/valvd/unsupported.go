//go:build !unix

package main

// Valv supports macOS, iOS and Linux only (SPEC 1). This undefined name makes
// the build fail with a message that says so.
var _ = valv_supports_only_macOS_iOS_and_Linux
