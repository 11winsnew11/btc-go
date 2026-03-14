package main

import (
    "crypto/sha256" // FIX 1: Import yang kurang tadi
    "encoding/hex"
    "flag"
    "fmt"
    "math"
    "math/bits"
    "os"
    "os/signal"
    "sync/atomic"
    "syscall"
    "time"

    "github.com/btcsuite/btcd/btcec/v2"
    "golang.org/x/crypto/ripemd160"

    "btc-go/random"
)

type Result struct {
    PrivKey    string
    Hash160    []byte
    Count      uint64
    Similarity float64
    Entropy    float64
}

func main() {
    targetHex2 := "bf7413e8df4e7a34ce"
    numWorkers := flag.Int("t", 4, "Jumlah thread (worker) yang digunakan")
    flag.Parse()

    if *numWorkers <= 0 {
        *numWorkers = 1
    }

    targetBytes, err := hex.DecodeString(targetHex2)
    if err != nil {
        fmt.Printf("Error: Target hex tidak valid (%v)\n", err)
        return
    }

    targetLen := len(targetBytes)
    totalBits := targetLen * 8

    // Kalkulasi Rentang Hamming untuk Similarity 0.55 - 0.57
    // Hamming = TotalBits * (1 - Similarity)
    minHamming := 27
    maxHamming := 38

    fmt.Printf("Searching with Optimized Filter...\n")
    fmt.Printf("Target (Hex2): %s\n", targetHex2)
    fmt.Printf("Criteria: BitSimilarity 0.55-0.57 (Hamming %d-%d), Entropy ~1.699\n", minHamming, maxHamming)
    fmt.Printf("Running with %d threads...\n", *numWorkers)
    fmt.Println("-------------------------------------------------------------")

    var totalCounter uint64 = 0
    // FIX 2: Hapus variabel 'foundCounter' yang tidak terpakai

    resultChan := make(chan Result, 100)
    stopChan := make(chan struct{})
    start := time.Now()

    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

    // Goroutine untuk menampilkan hasil
    go func() {
        for res := range resultChan {
            elapsed := time.Since(start)
            keysPerSec := float64(res.Count) / elapsed.Seconds()

            fmt.Printf("\n\n!!! FOUND MATCH !!!\n")
            fmt.Printf("Total Attempts : %d keys\n", res.Count)
            fmt.Printf("Keys/second    : %.2f\n", keysPerSec)
            fmt.Println("-------------------------------------------------------------")
            fmt.Printf("PrivKey        : %s\n", res.PrivKey)
            fmt.Printf("Hash160 (Hex1) : %x\n", res.Hash160[:targetLen])
            fmt.Printf("Bit Similarity : %.4f\n", res.Similarity)
            fmt.Printf("XOR Entropy    : %.4f\n", res.Entropy)
            fmt.Println("-------------------------------------------------------------")
        }
    }()

    // Worker
    for i := 0; i < *numWorkers; i++ {
        go func(workerID int) {
            localRng := random.NewHybrid(uint32(workerID) + uint32(time.Now().UnixNano()))
            ripemd160Hasher := ripemd160.New()
            xorBuf := make([]byte, targetLen)

            for {
                select {
                case <-stopChan:
                    return
                default:
                    currentCount := atomic.AddUint64(&totalCounter, 1)

                    // Generate Private Key
                    combined := localRng.CombineAllHex()
                    // Pastikan padding '0' benar (46 nol + 18 char combined = 64 char)
                    fullHex := "0000000000000000000000000000000000000000000000" + combined

                    privKeyBytes, err := hex.DecodeString(fullHex)
                    if err != nil {
                        continue
                    }

                    // Generate Public Key & Hash160
                    _, pubKey := btcec.PrivKeyFromBytes(privKeyBytes)
                    pubKeyBytes := pubKey.SerializeCompressed()

                    // SHA256
                    sha256Hash := sha256.Sum256(pubKeyBytes)

                    // RIPEMD160
                    ripemd160Hasher.Reset()
                    ripemd160Hasher.Write(sha256Hash[:])
                    hash160 := ripemd160Hasher.Sum(nil)

                    // --- OPTIMIZED CHECK ---
                    h1 := hash160[:targetLen]

                    // 1. Hitung Hamming Distance (Bit Difference)
                    hammingDist := 0
                    validRange := true

                    for k := 0; k < targetLen; k++ {
                        xorVal := h1[k] ^ targetBytes[k]
                        xorBuf[k] = xorVal
                        hammingDist += bits.OnesCount8(xorVal)

                        // Early exit: jika hamming sudah keluar dari jalur, hentikan loop
                        if hammingDist > maxHamming {
                            validRange = false
                            break
                        }
                    }

                    // 2. Filter Hamming (Target: 31 atau 32)
                    if validRange && hammingDist >= minHamming && hammingDist <= maxHamming {

                        // 3. Hitung Entropy Hanya jika Hamming cocok
                        entropy := calculateEntropyFast(xorBuf)

                        // Cek Entropy 1.699
                        if math.Round(entropy*1000) == 0 {
                            similarity := float64(totalBits-hammingDist) / float64(totalBits)

                            resultChan <- Result{
                                PrivKey:    fullHex,
                                Hash160:    hash160,
                                Count:      currentCount,
                                Similarity: similarity,
                                Entropy:    entropy,
                            }
                        }
                    }

                    if workerID == 0 && currentCount%100000 == 0 {
                        fmt.Printf("\rSpeed: %.2f keys/sec | Scanned: %d", float64(currentCount)/time.Since(start).Seconds(), currentCount)
                    }
                }
            }
        }(i)
    }

    <-sigChan
    fmt.Println("\n\nStopping...")
    close(stopChan)
    time.Sleep(500 * time.Millisecond)

    finalCount := atomic.LoadUint64(&totalCounter)
    elapsed := time.Since(start)
    fmt.Printf("Total keys: %d | Avg Speed: %.2f k/s\n", finalCount, float64(finalCount)/elapsed.Seconds())
}

func calculateEntropyFast(data []byte) float64 {
    if len(data) == 0 {
        return 0.0
    }
    counts := make(map[byte]int, 256)
    for _, b := range data {
        counts[b]++
    }

    total := float64(len(data))
    entropy := 0.0
    for _, c := range counts {
        p := float64(c) / total
        if p > 0 {
            entropy -= p * math.Log2(p)
        }
    }
    return math.Round(entropy*10000) / 10000
}