//go:build windows

package rendezvous

import (
	"os"
	"sync"
)

var epochPathLocks sync.Map

func validateEpochDirectorySecurity(os.FileInfo) error { return nil }

func validateEpochStateSecurity(os.FileInfo) error { return nil }

// Windows doesn't expose the same portable directory fsync semantics. The
// production OpenWrt implementation uses epoch_store_unix.go.
func syncEpochDirectory(string) error { return nil }

func lockEpochState(path string) (func(), error) {
	value, _ := epochPathLocks.LoadOrStore(path, &sync.Mutex{})
	mutex := value.(*sync.Mutex)
	mutex.Lock()
	return mutex.Unlock, nil
}
