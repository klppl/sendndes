package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klppl/sendndes/core"
)

type Worker struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.Reader
}

func startWorker(binPath string) (*Worker, error) {
	cmd := exec.Command(binPath)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &Worker{cmd: cmd, stdin: stdin, stdout: stdout}, nil
}

func (w *Worker) Call(cmd byte, payload []byte) (status byte, data []byte, err error) {
	var hdr [5]byte
	hdr[0] = cmd
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)))
	if _, err := w.stdin.Write(hdr[:]); err != nil {
		return 0, nil, fmt.Errorf("worker write header: %w", err)
	}
	if len(payload) > 0 {
		if _, err := w.stdin.Write(payload); err != nil {
			return 0, nil, fmt.Errorf("worker write payload: %w", err)
		}
	}
	var resHdr [5]byte
	if _, err := io.ReadFull(w.stdout, resHdr[:]); err != nil {
		return 0, nil, fmt.Errorf("worker read res header: %w", err)
	}
	status = resHdr[0]
	respLen := binary.BigEndian.Uint32(resHdr[1:5])
	data = make([]byte, respLen)
	if respLen > 0 {
		if _, err := io.ReadFull(w.stdout, data); err != nil {
			return 0, nil, fmt.Errorf("worker read res body: %w", err)
		}
	}
	return status, data, nil
}

func (w *Worker) Close() {
	_ = w.stdin.Close()
	_ = w.cmd.Wait()
}

func sha256Bytes(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func mutateBytes(src []byte, rng *rand.Rand) []byte {
	if len(src) == 0 {
		return []byte{byte(rng.Intn(256))}
	}
	b := bytes.Clone(src)
	op := rng.Intn(6)
	switch op {
	case 0:
		pos := rng.Intn(len(b))
		bit := rng.Intn(8)
		b[pos] ^= 1 << bit
	case 1:
		pos := rng.Intn(len(b))
		b[pos] = byte(rng.Intn(256))
	case 2:
		pos := rng.Intn(len(b))
		b = b[:pos]
	case 3:
		pos := rng.Intn(len(b) + 1)
		val := byte(rng.Intn(256))
		b = append(b[:pos], append([]byte{val}, b[pos:]...)...)
	case 4:
		if len(b) > 1 {
			pos := rng.Intn(len(b))
			b = append(b[:pos], b[pos+1:]...)
		}
	case 5:
		pos := rng.Intn(len(b))
		cnt := rng.Intn(len(b)-pos) + 1
		if rng.Intn(2) == 0 {
			for i := 0; i < cnt; i++ {
				b[pos+i] = 0
			}
		} else {
			for i := 0; i < cnt; i++ {
				b[pos+i] = byte(rng.Intn(256))
			}
		}
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type objSeed struct {
	name string
	data []byte
	id   core.FileID
}

func main() {
	workerFlag := flag.String("worker", "", "path to the built SwiftHarness binary")
	repoFlag := flag.String("repo", "../../..", "path to the Ndes repository root (for testvectors/)")
	cliFlag := flag.String("cli", "", "path to ndes CLI binary for real-process sample")
	swiftToolFlag := flag.String("swift-tool", "", "path to ndes-swift-tool binary for real-process sample")
	cliCasesFlag := flag.Int("cli-cases", 2000, "number of real-process sample cases")
	flag.Parse()
	if *workerFlag == "" && (*cliFlag == "" || *swiftToolFlag == "") {
		fmt.Println("usage: fuzzer [-worker <SwiftHarness>] [-cli <ndes> -swift-tool <ndes-swift-tool>] [-repo <repo root>]")
		os.Exit(2)
	}
	fmt.Println("=== Starting Ndes Differential Fuzzer (Go vs Swift) ===")

	repoDir := *repoFlag
	vaultJSONBytes, err := os.ReadFile(filepath.Join(repoDir, "testvectors/vault/vault.json"))
	if err != nil {
		fmt.Printf("FAIL: read vault.json: %v\n", err)
		os.Exit(1)
	}
	emptyObjBytes, _ := os.ReadFile(filepath.Join(repoDir, "testvectors/objects/empty.obj"))
	tinyObjBytes, _ := os.ReadFile(filepath.Join(repoDir, "testvectors/objects/tiny.obj"))
	exactObjBytes, _ := os.ReadFile(filepath.Join(repoDir, "testvectors/objects/exact.obj"))
	inboxInbBytes, _ := os.ReadFile(filepath.Join(repoDir, "testvectors/inbox/inbox.inb"))
	inboxObjBytes, _ := os.ReadFile(filepath.Join(repoDir, "testvectors/inbox/inbox_ingested.obj"))

	vectorsData, _ := os.ReadFile(filepath.Join(repoDir, "testvectors/vectors.json"))
	var vecMap struct {
		Vault struct {
			RecoveryKey string `json:"recovery_key"`
		} `json:"vault"`
		Objects []struct {
			File   string `json:"file"`
			FileID string `json:"file_id"`
			Path   string `json:"path"`
		} `json:"objects"`
		Inbox []struct {
			File   string `json:"file"`
			FileID string `json:"file_id"`
			Path   string `json:"path"`
		} `json:"inbox"`
		RecoveryKeys []struct {
			Input string `json:"input"`
		} `json:"recovery_keys"`
	}
	_ = json.Unmarshal(vectorsData, &vecMap)

	var tinyID, emptyID, exactID, inboxID core.FileID
	for _, o := range vecMap.Objects {
		fid, _ := core.ParseFileID(o.FileID)
		if strings.HasSuffix(o.File, "tiny.obj") {
			tinyID = fid
		} else if strings.HasSuffix(o.File, "empty.obj") {
			emptyID = fid
		} else if strings.HasSuffix(o.File, "exact.obj") {
			exactID = fid
		}
	}
	if len(vecMap.Inbox) > 0 {
		inboxID, _ = core.ParseFileID(vecMap.Inbox[0].FileID)
	}

	objSeeds := []objSeed{
		{"empty", emptyObjBytes, emptyID},
		{"tiny", tinyObjBytes, tinyID},
		{"exact", exactObjBytes, exactID},
	}

	if *workerFlag != "" {
		workerBin := *workerFlag
		worker, err := startWorker(workerBin)
		if err != nil {
			fmt.Printf("FAIL: Cannot start Swift worker: %v\n", err)
			os.Exit(1)
		}
		defer worker.Close()

		vkHex := "c660972aac797376ea9f855d87b834a1e8abf74fa2cb8940db2e92bfc5ea1ed4"
		var vkBytes [32]byte
		_, _ = hex.Decode(vkBytes[:], []byte(vkHex))
		vaultKeys, err := core.DeriveVaultKeys(vkBytes)
		if err != nil {
			fmt.Printf("FAIL: DeriveVaultKeys: %v\n", err)
			os.Exit(1)
		}

	rng := rand.New(rand.NewSource(0x5EED))

	var totalTests int64
	var totalMismatches int64
	var categoryStats = make(map[string]struct{ total, goAcc, swiftAcc, bothAcc int })

	runDiff := func(category string, cmd byte, payload []byte, goCheck func() ([]byte, error)) {
		atomic.AddInt64(&totalTests, 1)

		goOut, goErr := goCheck()
		goAccepted := (goErr == nil)

		swiftStatus, swiftData, err := worker.Call(cmd, payload)
		if err != nil {
			fmt.Printf("Worker IPC error in %s: %v\n", category, err)
			os.Exit(1)
		}
		swiftAccepted := (swiftStatus == 0)

		stat := categoryStats[category]
		stat.total++
		if goAccepted {
			stat.goAcc++
		}
		if swiftAccepted {
			stat.swiftAcc++
		}
		if goAccepted && swiftAccepted {
			stat.bothAcc++
		}
		categoryStats[category] = stat

		if goAccepted != swiftAccepted {
			atomic.AddInt64(&totalMismatches, 1)
			fmt.Printf("MISMATCH in %s: Go accepted=%v (err=%v), Swift accepted=%v (err=%s), payloadLen=%d\n",
				category, goAccepted, goErr, swiftAccepted, string(swiftData), len(payload))
			if totalMismatches >= 20 {
				fmt.Println("Too many mismatches, aborting early!")
				os.Exit(1)
			}
			return
		}

		if goAccepted && swiftAccepted {
			if !bytes.Equal(goOut, swiftData) {
				atomic.AddInt64(&totalMismatches, 1)
				fmt.Printf("OUTPUT DIFFERENCE in %s: Go output != Swift output! Go sha=%x, Swift sha=%x\n",
					category, sha256Bytes(goOut), sha256Bytes(swiftData))
				if totalMismatches >= 20 {
					fmt.Println("Too many mismatches, aborting early!")
					os.Exit(1)
				}
			}
		}
	}

	start := time.Now()

	// 1. FUZZ vault.json (4,500 cases)
	fmt.Println("Fuzzing vault.json (4,500 cases)...")
	runDiff("vault.json", 1, vaultJSONBytes, func() ([]byte, error) {
		cfg, err := core.ParseConfig(vaultJSONBytes)
		if err != nil {
			return nil, err
		}
		marshaled := cfg.Marshal()
		out := sha256Bytes(marshaled)
		return append(out, cfg.InboxPub[:]...), nil
	})

	for i := 0; i < 4499; i++ {
		var mutated []byte
		mode := rng.Intn(7)
		switch mode {
		case 0:
			mutated = mutateBytes(vaultJSONBytes, rng)
		case 1:
			s := string(vaultJSONBytes)
			insertions := []string{" ", "  ", "\t", "\n", "\r\n", "   "}
			pos := rng.Intn(len(s))
			mutated = []byte(s[:pos] + insertions[rng.Intn(len(insertions))] + s[pos:])
		case 2:
			s := string(vaultJSONBytes)
			extra := fmt.Sprintf(", \"extra_%d\": \"value_%d\"", rng.Intn(100), rng.Intn(100))
			idx := strings.LastIndex(s, "}")
			if idx > 0 {
				mutated = []byte(s[:idx] + extra + s[idx:])
			} else {
				mutated = []byte(s + extra)
			}
		case 3:
			s := string(vaultJSONBytes)
			tampering := []struct{ from, to string }{
				{`"v": 1`, fmt.Sprintf(`"v": %d`, rng.Intn(10)+2)},
				{`"v": 1`, `"v": "1"`},
				{`"v": 1`, `"v": 1.0`},
				{`"alg": "argon2id"`, `"alg": "argon2i"`},
				{`"alg": "argon2id"`, `"alg": "scrypt"`},
				{`"t": 3`, fmt.Sprintf(`"t": %d`, rng.Intn(10)+4)},
				{`"m_kib": 65536`, fmt.Sprintf(`"m_kib": %d`, rng.Intn(10000))},
				{`"p": 1`, fmt.Sprintf(`"p": %d`, rng.Intn(10)+2)},
				{`"wrapped_vk": "`, `"wrapped_vk": "AA==`},
				{`"inbox_pub": "`, `"inbox_pub": "AA==`},
			}
			t := tampering[rng.Intn(len(tampering))]
			mutated = []byte(strings.Replace(s, t.from, t.to, 1))
		case 4:
			s := string(vaultJSONBytes)
			mutated = []byte(strings.Replace(s, "salt\": \"", "salt\": \"====", 1))
		case 5:
			mutated = append(bytes.Clone(vaultJSONBytes), bytes.Repeat([]byte(" "), 4097)...)
		case 6:
			mutated = make([]byte, rng.Intn(500)+1)
			rng.Read(mutated)
		}

		runDiff("vault.json", 1, mutated, func() ([]byte, error) {
			cfg, err := core.ParseConfig(mutated)
			if err != nil {
				return nil, err
			}
			marshaled := cfg.Marshal()
			out := sha256Bytes(marshaled)
			return append(out, cfg.InboxPub[:]...), nil
		})
	}

	// 2. FUZZ Metadata raw padded bytes (4,500 cases)
	fmt.Println("Fuzzing Metadata (4,500 cases)...")
	baseMeta := core.Metadata{
		Name:  "fuzz.txt",
		Dir:   "docs/sub",
		MTime: 1729000000000000000,
		MIME:  "text/plain",
		Rev:   1,
	}
	basePadded, _, _ := core.EncodeMetadata(baseMeta)

	for i := 0; i < 4500; i++ {
		var mutated []byte
		mode := rng.Intn(7)
		switch mode {
		case 0:
			mutated = mutateBytes(basePadded, rng)
		case 1:
			mutated = bytes.Clone(basePadded)
			delta := rng.Intn(511) + 1
			if rng.Intn(2) == 0 && len(mutated) > delta {
				mutated = mutated[:len(mutated)-delta]
			} else {
				mutated = append(mutated, bytes.Repeat([]byte{0x20}, delta)...)
			}
		case 2:
			mutated = bytes.Clone(basePadded)
			nonSpace := []byte{0x00, 0x09, 0x0A, 0x0D, 'a', '0'}
			pos := len(mutated) - rng.Intn(50) - 1
			if pos >= 0 && pos < len(mutated) {
				mutated[pos] = nonSpace[rng.Intn(len(nonSpace))]
			}
		case 3:
			mutated = append(bytes.Clone(basePadded), bytes.Repeat([]byte{0x20}, 512)...)
		case 4:
			m := core.Metadata{
				Name:  fmt.Sprintf("file_%d.dat", rng.Intn(100)),
				Dir:   fmt.Sprintf("dir_%d", rng.Intn(10)),
				MTime: rng.Int63(),
				MIME:  "application/octet-stream",
				Rev:   int64(rng.Intn(100) + 1),
			}
			if rng.Intn(4) == 0 {
				m.Rev = int64(rng.Intn(5) - 3)
			}
			if rng.Intn(4) == 0 {
				m.Name = []string{"", ".", "..", "a/b", "a\x00b"}[rng.Intn(5)]
			}
			if rng.Intn(4) == 0 {
				m.Dir = []string{"/a", "a/", "a//b", "a/./b", "a/../b"}[rng.Intn(5)]
			}
			encoded, _, err := core.EncodeMetadata(m)
			if err != nil {
				mutated = []byte(fmt.Sprintf(`{"name":"%s","dir":"%s","mtime":%d,"mime":"","rev":%d}`,
					m.Name, m.Dir, m.MTime, m.Rev))
				padLen := 512 - (len(mutated) % 512)
				if padLen < 512 {
					mutated = append(mutated, bytes.Repeat([]byte{0x20}, padLen)...)
				}
			} else {
				mutated = encoded
			}
		case 5:
			escapes := []string{`\u0000`, `\u001f`, `\u0020`, `\u0041`, `\n`, `\t`, `\r`, `\/`}
			esc := escapes[rng.Intn(len(escapes))]
			rawJSON := fmt.Sprintf(`{"name":"test%s","dir":"","mtime":123,"mime":"","rev":1}`, esc)
			padLen := 512 - (len(rawJSON) % 512)
			mutated = append([]byte(rawJSON), bytes.Repeat([]byte{0x20}, padLen)...)
		case 6:
			mutated = make([]byte, rng.Intn(2048))
			rng.Read(mutated)
		}

		runDiff("metadata", 2, mutated, func() ([]byte, error) {
			m, err := core.DecodeMetadata(mutated)
			if err != nil {
				return nil, err
			}
			metaStr := fmt.Sprintf("%s|%s|%d|%s|%d", m.Name, m.Dir, m.MTime, m.MIME, m.Rev)
			return sha256Bytes([]byte(metaStr)), nil
		})
	}

	// 3. FUZZ .obj files (6,500 cases)
	fmt.Println("Fuzzing Object files (6,500 cases)...")

	for i := 0; i < 6500; i++ {
		seed := objSeeds[rng.Intn(len(objSeeds))]
		var mutated []byte
		var expectedID core.FileID = seed.id

		mode := rng.Intn(8)
		switch mode {
		case 0: // unmutated valid seed
			mutated = bytes.Clone(seed.data)
		case 1:
			mutated = mutateBytes(seed.data, rng)
		case 2:
			mutated = bytes.Clone(seed.data)
			offset := rng.Intn(min(86, len(mutated)))
			mutated[offset] = byte(rng.Intn(256))
		case 3:
			mutated = bytes.Clone(seed.data)
			if len(mutated) >= 86 {
				badLens := []uint32{0, 28, 512, 539, 541, 65565, 70000, 0xFFFFFFFF}
				bl := badLens[rng.Intn(len(badLens))]
				binary.BigEndian.PutUint32(mutated[82:86], bl)
			}
		case 4:
			mutated = bytes.Clone(seed.data)
			if len(mutated) >= 86 {
				metaLen := int(binary.BigEndian.Uint32(mutated[82:86]))
				hdrLen := 86 + metaLen
				targetCtTotals := []int{0, 1, 15, 65552 + 1, 65552 + 15, 65552 + 16, 131104 + 16}
				target := targetCtTotals[rng.Intn(len(targetCtTotals))]
				newTotal := hdrLen + target
				if newTotal > len(mutated) {
					mutated = append(mutated, make([]byte, newTotal-len(mutated))...)
				} else if newTotal > 0 {
					mutated = mutated[:newTotal]
				}
			}
		case 5:
			mutated = bytes.Clone(seed.data)
			if len(mutated) > 86+540 {
				pos := 86 + 540 + rng.Intn(len(mutated)-(86+540))
				mutated[pos] ^= byte(rng.Intn(255) + 1)
			}
		case 6:
			mutated = bytes.Clone(seed.data)
			expectedID = core.FileID{}
			rng.Read(expectedID[:])
		case 7:
			mutated = bytes.Clone(seed.data)
			cut := rng.Intn(len(mutated))
			mutated = mutated[:cut]
		}

		payload := append(expectedID[:], mutated...)
		runDiff("objects", 3, payload, func() ([]byte, error) {
			var out bytes.Buffer
			meta, err := core.DecryptObject(bytes.NewReader(mutated), int64(len(mutated)), expectedID, vaultKeys, &out)
			if err != nil {
				return nil, err
			}
			metaStr := fmt.Sprintf("%s|%s|%d|%s|%d", meta.Name, meta.Dir, meta.MTime, meta.MIME, meta.Rev)
			res := sha256Bytes(out.Bytes())
			res = append(res, sha256Bytes([]byte(metaStr))...)
			return res, nil
		})
	}

	// 4. FUZZ .inb inbox files & Ingest (4,500 cases)
	fmt.Println("Fuzzing Inbox & Ingest (4,500 cases)...")
	for i := 0; i < 4500; i++ {
		var mutated []byte
		var expectedID core.FileID = inboxID

		mode := rng.Intn(8)
		switch mode {
		case 0: // unmutated valid seed
			mutated = bytes.Clone(inboxInbBytes)
		case 1:
			mutated = mutateBytes(inboxInbBytes, rng)
		case 2:
			mutated = bytes.Clone(inboxInbBytes)
			offset := rng.Intn(min(58, len(mutated)))
			mutated[offset] = byte(rng.Intn(256))
		case 3:
			mutated = bytes.Clone(inboxInbBytes)
			if len(mutated) >= 58 {
				badLens := []uint32{0, 28, 512, 539, 541, 65565, 70000, 0xFFFFFFFF}
				bl := badLens[rng.Intn(len(badLens))]
				binary.BigEndian.PutUint32(mutated[54:58], bl)
			}
		case 4:
			mutated = bytes.Clone(inboxInbBytes)
			if len(mutated) >= 54 {
				if rng.Intn(2) == 0 {
					for k := 22; k < 54; k++ {
						mutated[k] = 0
					}
				} else {
					mutated[22+rng.Intn(32)] ^= 0xFF
				}
			}
		case 5:
			mutated = bytes.Clone(inboxInbBytes)
			if len(mutated) > 58+540 {
				pos := 58 + 540 + rng.Intn(len(mutated)-(58+540))
				mutated[pos] ^= byte(rng.Intn(255) + 1)
			}
		case 6:
			mutated = bytes.Clone(inboxInbBytes)
			expectedID = core.FileID{}
			rng.Read(expectedID[:])
		case 7:
			mutated = bytes.Clone(inboxInbBytes)
			cut := rng.Intn(len(mutated))
			mutated = mutated[:cut]
		}

		payload := append(expectedID[:], mutated...)
		runDiff("inbox-decrypt", 4, payload, func() ([]byte, error) {
			var objBuf bytes.Buffer
			meta, err := core.IngestInbox(bytes.NewReader(mutated), int64(len(mutated)), expectedID, vaultKeys, &objBuf)
			if err != nil {
				return nil, err
			}
			var plainBuf bytes.Buffer
			_, err = core.DecryptObject(bytes.NewReader(objBuf.Bytes()), int64(objBuf.Len()), expectedID, vaultKeys, &plainBuf)
			if err != nil {
				return nil, err
			}
			metaStr := fmt.Sprintf("%s|%s|%d|%s|%d", meta.Name, meta.Dir, meta.MTime, meta.MIME, meta.Rev)
			res := sha256Bytes(plainBuf.Bytes())
			res = append(res, sha256Bytes([]byte(metaStr))...)
			return res, nil
		})
	}

	// 5. FUZZ Recovery Keys (3,000 cases)
	fmt.Println("Fuzzing Recovery Keys (3,000 cases)...")
	baseRecoveryKey := vecMap.Vault.RecoveryKey
	b32Alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

	for i := 0; i < 3000; i++ {
		var inputStr string
		mode := rng.Intn(6)
		switch mode {
		case 0:
			chars := []byte(baseRecoveryKey)
			var mutatedChars []byte
			for _, c := range chars {
				if c >= 'A' && c <= 'Z' && rng.Intn(2) == 0 {
					c += 32
				}
				if rng.Intn(10) == 0 {
					mutatedChars = append(mutatedChars, ' ')
				}
				if rng.Intn(10) == 0 {
					mutatedChars = append(mutatedChars, '-')
				}
				mutatedChars = append(mutatedChars, c)
			}
			inputStr = string(mutatedChars)
		case 1:
			chars := []byte(baseRecoveryKey)
			pos := rng.Intn(len(chars))
			for chars[pos] == '-' || chars[pos] == ' ' {
				pos = rng.Intn(len(chars))
			}
			orig := chars[pos]
			newChar := b32Alphabet[rng.Intn(len(b32Alphabet))]
			for newChar == orig {
				newChar = b32Alphabet[rng.Intn(len(b32Alphabet))]
			}
			chars[pos] = newChar
			inputStr = string(chars)
		case 2:
			chars := []byte(baseRecoveryKey)
			clean := strings.ReplaceAll(strings.ReplaceAll(string(chars), "-", ""), " ", "")
			cut := rng.Intn(len(clean) + 10)
			if cut <= len(clean) {
				inputStr = clean[:cut]
			} else {
				inputStr = clean + strings.Repeat("A", cut-len(clean))
			}
		case 3:
			invalidChars := []string{"0", "1", "8", "9", "!", "?", "é", "한", "§"}
			inv := invalidChars[rng.Intn(len(invalidChars))]
			s := baseRecoveryKey
			pos := rng.Intn(len(s))
			inputStr = s[:pos] + inv + s[pos:]
		case 4:
			if len(vecMap.RecoveryKeys) > 0 {
				vkSample := vecMap.RecoveryKeys[rng.Intn(len(vecMap.RecoveryKeys))]
				inputStr = vkSample.Input
			} else {
				inputStr = baseRecoveryKey + "X"
			}
		case 5:
			l := rng.Intn(70) + 1
			buf := make([]byte, l)
			for j := 0; j < l; j++ {
				buf[j] = b32Alphabet[rng.Intn(len(b32Alphabet))]
			}
			inputStr = string(buf)
		}

		runDiff("recovery-keys", 6, []byte(inputStr), func() ([]byte, error) {
			vk, err := core.DecodeRecoveryKey(inputStr)
			if err != nil {
				return nil, err
			}
			return vk[:], nil
		})
	}

	// 6. FUZZ Paths (1,000 cases)
	fmt.Println("Fuzzing Paths (1,000 cases)...")
	hexChars := "0123456789abcdef"
	for i := 0; i < 500; i++ {
		var testPath string
		mode := rng.Intn(5)
		id := make([]byte, 32)
		for j := 0; j < 32; j++ {
			id[j] = hexChars[rng.Intn(len(hexChars))]
		}
		idStr := string(id)
		switch mode {
		case 0:
			testPath = fmt.Sprintf("objects/%s/%s.obj", idStr[:2], idStr)
		case 1:
			testPath = fmt.Sprintf("objects/%s/%s.obj", strings.ToUpper(idStr[:2]), strings.ToUpper(idStr))
		case 2:
			testPath = fmt.Sprintf("objects/%s/%s.obj", "ff", idStr)
		case 3:
			testPath = fmt.Sprintf("wrong/%s/%s.obj", idStr[:2], idStr)
		case 4:
			testPath = fmt.Sprintf("objects/%s/%s.inb", idStr[:2], idStr)
		}

		runDiff("object-paths", 7, []byte(testPath), func() ([]byte, error) {
			fid, err := core.ParseObjectPath(testPath)
			if err != nil {
				return nil, err
			}
			return fid[:], nil
		})
	}

	for i := 0; i < 500; i++ {
		var testPath string
		mode := rng.Intn(4)
		id := make([]byte, 32)
		for j := 0; j < 32; j++ {
			id[j] = hexChars[rng.Intn(len(hexChars))]
		}
		idStr := string(id)
		switch mode {
		case 0:
			testPath = fmt.Sprintf("inbox/%s.inb", idStr)
		case 1:
			testPath = fmt.Sprintf("inbox/%s.inb", strings.ToUpper(idStr))
		case 2:
			testPath = fmt.Sprintf("other/%s.inb", idStr)
		case 3:
			testPath = fmt.Sprintf("inbox/%s.obj", idStr)
		}

		runDiff("inbox-paths", 8, []byte(testPath), func() ([]byte, error) {
			parts := strings.Split(testPath, "/")
			if len(parts) != 2 || parts[0] != "inbox" {
				return nil, fmt.Errorf("%w: path not in inbox", core.ErrPathMismatch)
			}
			fid, err := core.ParseInboxName(parts[1])
			if err != nil {
				return nil, err
			}
			return fid[:], nil
		})
	}

	// 7. FUZZ Ingest Idempotency (1,000 cases)
	fmt.Println("Fuzzing Ingest Idempotency (1,000 cases)...")
	for i := 0; i < 1000; i++ {
		var inbData []byte = bytes.Clone(inboxInbBytes)
		var objData []byte = bytes.Clone(inboxObjBytes)
		mode := rng.Intn(5)
		switch mode {
		case 0:
			// identical matching pair
		case 1:
			if len(objData) > 50 {
				objData[40] ^= 0x01
			}
		case 2:
			if len(objData) > 100 {
				objData[len(objData)-1] ^= 0x01
			}
		case 3:
			if len(inbData) > 60 {
				inbData[58] ^= 0x01
			}
		case 4:
			if len(inbData) > 100 {
				inbData[len(inbData)-1] ^= 0x01
			}
		}

		var payload []byte
		payload = append(payload, inboxID[:]...)
		var inbLenBytes [4]byte
		binary.BigEndian.PutUint32(inbLenBytes[:], uint32(len(inbData)))
		payload = append(payload, inbLenBytes[:]...)
		payload = append(payload, inbData...)
		payload = append(payload, objData...)

		runDiff("idempotency", 9, payload, func() ([]byte, error) {
			err := core.CheckAlreadyIngested(
				bytes.NewReader(inbData), int64(len(inbData)),
				bytes.NewReader(objData), int64(len(objData)),
				inboxID, vaultKeys,
			)
			if err == nil {
				return []byte{1}, nil
			}
			if errors.Is(err, core.ErrConflict) {
				return []byte{0}, nil
			}
			return nil, err
		})
	}

	elapsed := time.Since(start)
	fmt.Println("\n================ FUZZER RESULTS SUMMARY ================")
	fmt.Printf("Total inputs executed: %d in %.2fs (%.1f tests/sec)\n",
		totalTests, elapsed.Seconds(), float64(totalTests)/elapsed.Seconds())
	fmt.Printf("Total mismatches:      %d\n", totalMismatches)
	fmt.Println("---------------------------------------------------------")
	for cat, st := range categoryStats {
		fmt.Printf("  %-16s: %5d tests | Go acc: %5d | Swift acc: %5d | Both acc: %5d\n",
			cat, st.total, st.goAcc, st.swiftAcc, st.bothAcc)
	}
	fmt.Println("=========================================================")

		if totalMismatches == 0 && totalTests >= 20000 {
			fmt.Println("RESULT: ALL DIFFERENTIAL FUZZING CHECKS PASSED PERFECTLY!")
		} else {
			fmt.Printf("RESULT: FAILED with %d mismatches or insufficient tests (%d < 20000)\n", totalMismatches, totalTests)
			os.Exit(1)
		}
	}

	if *cliFlag != "" && *swiftToolFlag != "" {
		runCLISample(*cliFlag, *swiftToolFlag, repoDir, *cliCasesFlag, objSeeds, vaultJSONBytes)
	}
}

func runCLISample(cliBin, swiftToolBin, repoDir string, totalCases int, objSeeds []objSeed, vaultJSON []byte) {
	fmt.Printf("\n=== Running Real-Process CLI Sample (%d cases / %d Argon2id processes) ===\n", totalCases, totalCases*2)
	cliBin, err := filepath.Abs(cliBin)
	if err != nil {
		fmt.Printf("FAIL: cli path %v\n", err)
		os.Exit(1)
	}
	swiftToolBin, err = filepath.Abs(swiftToolBin)
	if err != nil {
		fmt.Printf("FAIL: swift tool path %v\n", err)
		os.Exit(1)
	}

	workers := runtime.NumCPU()
	if workers < 4 {
		workers = 4
	}
	if workers > 16 {
		workers = 16
	}
	casesPerWorker := (totalCases + workers - 1) / workers

	var mismatches atomic.Int64
	var goAccepted atomic.Int64
	var swiftAccepted atomic.Int64
	var bothAccepted atomic.Int64
	var completed atomic.Int64

	var wg sync.WaitGroup
	start := time.Now()
	passphrase := "correct horse battery staple\n"

	for w := 0; w < workers; w++ {
		wID := w
		startIdx := w * casesPerWorker
		endIdx := startIdx + casesPerWorker
		if endIdx > totalCases {
			endIdx = totalCases
		}
		if startIdx >= endIdx {
			continue
		}
		wg.Add(1)
		go func(startCase, endCase int) {
			defer wg.Done()
			tmp, err := os.MkdirTemp("", fmt.Sprintf("ndes-cli-fuzz-%d-*", wID))
			if err != nil {
				fmt.Printf("Worker %d mkdir: %v\n", wID, err)
				mismatches.Add(1)
				return
			}
			defer os.RemoveAll(tmp)

			vaultDir := filepath.Join(tmp, "vault")
			_ = os.MkdirAll(vaultDir, 0700)
			_ = os.WriteFile(filepath.Join(vaultDir, "vault.json"), vaultJSON, 0600)

			wRng := rand.New(rand.NewSource(int64(0x5EED + startCase)))

			for i := startCase; i < endCase; i++ {
				seed := objSeeds[wRng.Intn(len(objSeeds))]
				var mutated []byte

				mode := wRng.Intn(8)
				switch mode {
				case 0:
					mutated = bytes.Clone(seed.data)
				case 1:
					mutated = mutateBytes(seed.data, wRng)
				case 2:
					mutated = bytes.Clone(seed.data)
					offset := wRng.Intn(min(86, len(mutated)))
					mutated[offset] = byte(wRng.Intn(256))
				case 3:
					mutated = bytes.Clone(seed.data)
					if len(mutated) >= 86 {
						badLens := []uint32{0, 28, 512, 539, 541, 65565, 70000, 0xFFFFFFFF}
						bl := badLens[wRng.Intn(len(badLens))]
						binary.BigEndian.PutUint32(mutated[82:86], bl)
					}
				case 4:
					mutated = bytes.Clone(seed.data)
					if len(mutated) >= 86 {
						metaLen := int(binary.BigEndian.Uint32(mutated[82:86]))
						hdrLen := 86 + metaLen
						targetCtTotals := []int{0, 1, 15, 65552 + 1, 65552 + 15, 65552 + 16, 131104 + 16}
						target := targetCtTotals[wRng.Intn(len(targetCtTotals))]
						newTotal := hdrLen + target
						if newTotal > len(mutated) {
							mutated = append(mutated, make([]byte, newTotal-len(mutated))...)
						} else if newTotal > 0 {
							mutated = mutated[:newTotal]
						}
					}
				case 5:
					mutated = bytes.Clone(seed.data)
					if len(mutated) > 86+540 {
						pos := 86 + 540 + wRng.Intn(len(mutated)-(86+540))
						mutated[pos] ^= byte(wRng.Intn(255) + 1)
					}
				case 6:
					mutated = bytes.Clone(seed.data)
					if len(mutated) >= 22 {
						mutated[wRng.Intn(22)] ^= byte(wRng.Intn(255) + 1)
					}
				case 7:
					mutated = bytes.Clone(seed.data)
					cut := wRng.Intn(len(mutated))
					mutated = mutated[:cut]
				}

				idHex := seed.id.String()
				objDir := filepath.Join(vaultDir, "objects", idHex[:2])
				_ = os.MkdirAll(objDir, 0700)
				objPath := filepath.Join(objDir, idHex+".obj")
				_ = os.WriteFile(objPath, mutated, 0600)

				outGo := filepath.Join(tmp, fmt.Sprintf("out_go_%d", i))
				outSwift := filepath.Join(tmp, fmt.Sprintf("out_sw_%d", i))

				// Run Go CLI
				cmdGo := exec.Command(cliBin, "get", idHex, "-o="+outGo, "--vault="+vaultDir, "--passphrase-stdin")
				cmdGo.Stdin = strings.NewReader(passphrase)
				goErr := cmdGo.Run()
				goOk := (goErr == nil)

				// Run Swift tool
				cmdSwift := exec.Command(swiftToolBin, "decrypt-object", filepath.Join(vaultDir, "vault.json"), objPath, outSwift)
				cmdSwift.Stdin = strings.NewReader(passphrase)
				swErr := cmdSwift.Run()
				swOk := (swErr == nil)

				if goOk {
					goAccepted.Add(1)
				}
				if swOk {
					swiftAccepted.Add(1)
				}
				if goOk && swOk {
					bothAccepted.Add(1)
					bGo, _ := os.ReadFile(outGo)
					bSw, _ := os.ReadFile(outSwift)
					if !bytes.Equal(bGo, bSw) {
						mismatches.Add(1)
						fmt.Printf("CLI OUTPUT DIFFERENCE at case %d: Go len=%d, Swift len=%d\n", i, len(bGo), len(bSw))
					}
				} else if goOk != swOk {
					mismatches.Add(1)
					fmt.Printf("CLI MISMATCH at case %d: Go ok=%v (err=%v), Swift ok=%v (err=%v), mutatedLen=%d\n",
						i, goOk, goErr, swOk, swErr, len(mutated))
				}

				_ = os.Remove(objPath)
				_ = os.Remove(outGo)
				_ = os.Remove(outSwift)

				done := completed.Add(1)
				if done%500 == 0 || done == int64(totalCases) {
					fmt.Printf("  Progress: %d/%d cases done (%.1fs)...\n", done, totalCases, time.Since(start).Seconds())
				}
			}
		}(startIdx, endIdx)
	}

	wg.Wait()
	elapsed := time.Since(start)
	fmt.Println("---------------------------------------------------------")
	fmt.Printf("CLI Sample Summary: %d cases in %.2fs (%.1f cases/sec)\n", totalCases, elapsed.Seconds(), float64(totalCases)/elapsed.Seconds())
	fmt.Printf("  Go accepted:    %d\n", goAccepted.Load())
	fmt.Printf("  Swift accepted: %d\n", swiftAccepted.Load())
	fmt.Printf("  Both accepted:  %d\n", bothAccepted.Load())
	fmt.Printf("  CLI mismatches: %d\n", mismatches.Load())
	fmt.Println("=========================================================")
	if mismatches.Load() > 0 {
		fmt.Printf("RESULT: FAILED with %d CLI mismatches\n", mismatches.Load())
		os.Exit(1)
	}
}
