package main

import "testing"

func TestDropPrivilegesNoopWithoutConfig(t *testing.T) {
	t.Setenv("VALVD_RUN_AS", "")
	if err := dropPrivileges(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}
