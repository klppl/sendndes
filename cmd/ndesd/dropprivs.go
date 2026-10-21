package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// dropPrivileges is for containers. When ndesd starts as root and
// NDESD_RUN_AS=uid:gid is set, it makes dataDir (and everything in it) belong
// to that user, then switches to it before anything is served. A fresh volume,
// an old root-owned volume and a bind mount all work without manual chown.
// Without root or without the variable it does nothing.
func dropPrivileges(dataDir string) error {
	spec := os.Getenv("NDESD_RUN_AS")
	if spec == "" || os.Geteuid() != 0 {
		return nil
	}
	us, gs, ok := strings.Cut(spec, ":")
	uid, uerr := strconv.Atoi(us)
	gid, gerr := strconv.Atoi(gs)
	if !ok || uerr != nil || gerr != nil || uid <= 0 || gid <= 0 {
		return fmt.Errorf("NDESD_RUN_AS must be uid:gid with non-zero ids, got %q", spec)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	err := filepath.WalkDir(dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) == uid && int(st.Gid) == gid {
			return nil
		}
		return os.Lchown(path, uid, gid)
	})
	if err != nil {
		return fmt.Errorf("chown %s: %w", dataDir, err)
	}
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return err
	}
	if err := syscall.Setgid(gid); err != nil {
		return err
	}
	return syscall.Setuid(uid)
}
