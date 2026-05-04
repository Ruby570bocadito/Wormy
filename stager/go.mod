module wormy-stager

go 1.21

require (
	// No external deps — pure stdlib for maximum stealth.
	// Optional: uncomment for full feature set
	// golang.org/x/crypto v0.17.0   // X25519 ECDH PFS
	// github.com/lesnuages/go-winio v0.6.1  // Named pipe C2
)
