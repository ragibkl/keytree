package authkeys

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// MaxFileSize caps how much of an existing authorized_keys is read.
const MaxFileSize = 1 << 20

const (
	sshDir   = ".ssh"
	fileName = "authorized_keys"
	tmpPref  = ".authorized_keys.keytree-"
)

// Account is a local account whose authorized_keys keytree manages.
type Account struct {
	Name string
	UID  int
	GID  int
	// Home is the home directory as seen by this process (already joined
	// with any --root prefix).
	Home string
}

// Update makes the managed block in the account's ~/.ssh/authorized_keys
// hold exactly lines (no lines removes the block). It reports whether the
// file changed, or would change with dryRun.
//
// Everything below the home directory is user-controlled, so it is reached
// through directory file descriptors with O_NOFOLLOW: a symlinked ~/.ssh or
// authorized_keys is refused, never followed.
func Update(acct Account, lines []string, dryRun bool) (bool, error) {
	home, err := unix.Open(acct.Home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, fmt.Errorf("home %s: %w", acct.Home, err)
	}
	defer unix.Close(home)

	dir, err := openSSHDir(home, acct)
	if errors.Is(err, unix.ENOENT) {
		if len(lines) == 0 || dryRun {
			return len(lines) > 0, nil
		}
		dir, err = createSSHDir(home, acct)
	}
	if err != nil {
		return false, err
	}
	defer unix.Close(dir)

	if !dryRun {
		removeStaleTemps(dir)
	}

	old, err := readKeysFile(dir, acct)
	if err != nil {
		return false, err
	}
	next, err := Apply(old, lines)
	if err != nil {
		return false, fmt.Errorf("~%s/.ssh/authorized_keys: %w", acct.Name, err)
	}
	if bytes.Equal(old, next) {
		return false, nil
	}
	if dryRun {
		return true, nil
	}
	if err := writeKeysFile(dir, acct, next); err != nil {
		return false, err
	}
	return true, nil
}

// Read returns the lines currently in the account's managed block.
func Read(acct Account) ([]string, error) {
	home, err := unix.Open(acct.Home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("home %s: %w", acct.Home, err)
	}
	defer unix.Close(home)
	dir, err := openSSHDir(home, acct)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	content, err := readKeysFile(dir, acct)
	if err != nil {
		return nil, err
	}
	return Lines(content)
}

func openSSHDir(home int, acct Account) (int, error) {
	fd, err := unix.Openat(home, sshDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return -1, err
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
		return -1, fmt.Errorf("~%s/.ssh is a symlink or not a directory; refusing to touch it", acct.Name)
	case err != nil:
		return -1, fmt.Errorf("~%s/.ssh: %w", acct.Name, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("~%s/.ssh: %w", acct.Name, err)
	}
	if int(st.Uid) != acct.UID {
		unix.Close(fd)
		return -1, fmt.Errorf("~%s/.ssh is owned by uid %d, not %d; refusing to touch it", acct.Name, st.Uid, acct.UID)
	}
	if st.Mode&0o022 != 0 {
		unix.Close(fd)
		return -1, fmt.Errorf("~%s/.ssh is group- or world-writable (%#o); refusing to touch it", acct.Name, st.Mode&0o777)
	}
	return fd, nil
}

func createSSHDir(home int, acct Account) (int, error) {
	if err := unix.Mkdirat(home, sshDir, 0o700); err != nil {
		return -1, fmt.Errorf("create ~%s/.ssh: %w", acct.Name, err)
	}
	fd, err := unix.Openat(home, sshDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open new ~%s/.ssh: %w", acct.Name, err)
	}
	if err := unix.Fchown(fd, acct.UID, acct.GID); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("chown ~%s/.ssh: %w", acct.Name, err)
	}
	if err := unix.Fchmod(fd, 0o700); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("chmod ~%s/.ssh: %w", acct.Name, err)
	}
	return fd, nil
}

// readKeysFile returns the current authorized_keys, or nil if there is none.
// Checks run on the opened descriptor, so the file can't be swapped between
// check and read.
func readKeysFile(dir int, acct Account) ([]byte, error) {
	fd, err := unix.Openat(dir, fileName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return nil, nil
	case errors.Is(err, unix.ELOOP):
		return nil, fmt.Errorf("~%s/.ssh/authorized_keys is a symlink; refusing to touch it", acct.Name)
	case err != nil:
		return nil, fmt.Errorf("~%s/.ssh/authorized_keys: %w", acct.Name, err)
	}
	f := os.NewFile(uintptr(fd), fileName)
	defer f.Close()

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("~%s/.ssh/authorized_keys: %w", acct.Name, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return nil, fmt.Errorf("~%s/.ssh/authorized_keys is not a regular file; refusing to touch it", acct.Name)
	case int(st.Uid) != acct.UID:
		return nil, fmt.Errorf("~%s/.ssh/authorized_keys is owned by uid %d, not %d; refusing to touch it", acct.Name, st.Uid, acct.UID)
	case st.Nlink != 1:
		return nil, fmt.Errorf("~%s/.ssh/authorized_keys has %d hard links; refusing to touch it", acct.Name, st.Nlink)
	case st.Size > MaxFileSize:
		return nil, fmt.Errorf("~%s/.ssh/authorized_keys is larger than %d bytes", acct.Name, MaxFileSize)
	}
	content, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read ~%s/.ssh/authorized_keys: %w", acct.Name, err)
	}
	if len(content) > MaxFileSize {
		return nil, fmt.Errorf("~%s/.ssh/authorized_keys is larger than %d bytes", acct.Name, MaxFileSize)
	}
	return content, nil
}

// testHookBeforeRename lets tests simulate a crash between write and rename.
var testHookBeforeRename func() error

// writeKeysFile replaces authorized_keys atomically: write a temp file in the
// same directory, fsync it, then rename it over the old one.
func writeKeysFile(dir int, acct Account, content []byte) (err error) {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := tmpPref + hex.EncodeToString(rnd[:])
	fd, err := unix.Openat(dir, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create temp file in ~%s/.ssh: %w", acct.Name, err)
	}
	f := os.NewFile(uintptr(fd), tmp)
	defer func() {
		f.Close()
		if err != nil {
			unix.Unlinkat(dir, tmp, 0)
		}
	}()

	if err := unix.Fchown(fd, acct.UID, acct.GID); err != nil {
		return fmt.Errorf("chown ~%s/.ssh/authorized_keys: %w", acct.Name, err)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return fmt.Errorf("chmod ~%s/.ssh/authorized_keys: %w", acct.Name, err)
	}
	if _, err := f.Write(content); err != nil {
		return fmt.Errorf("write ~%s/.ssh/authorized_keys: %w", acct.Name, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync ~%s/.ssh/authorized_keys: %w", acct.Name, err)
	}
	if testHookBeforeRename != nil {
		if err := testHookBeforeRename(); err != nil {
			return err
		}
	}
	if err := unix.Renameat(dir, tmp, dir, fileName); err != nil {
		return fmt.Errorf("replace ~%s/.ssh/authorized_keys: %w", acct.Name, err)
	}
	return unix.Fsync(dir)
}

// removeStaleTemps deletes temp files left by a run that died mid-write.
func removeStaleTemps(dir int) {
	dup, err := unix.Dup(dir)
	if err != nil {
		return
	}
	d := os.NewFile(uintptr(dup), sshDir)
	defer d.Close()
	names, _ := d.Readdirnames(-1)
	for _, n := range names {
		if strings.HasPrefix(n, tmpPref) {
			unix.Unlinkat(dir, n, 0)
		}
	}
}
