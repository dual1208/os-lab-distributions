//go:build !linux

package credential

import "os"

// Linux is the production target. Other platforms retain the portable
// no-symlink/regular-file checks; their ACL and ownership models are not
// approximated with Unix mode bits.
func validatePlatformPolicy(_ os.FileInfo, _ bool, _ Kind) error {
	return nil
}
