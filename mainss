package main

import (
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "flag"
    "fmt"
    "os"
    "os/signal"
    "strings"
    "sync/atomic"
    "syscall"
    "time"

    "github.com/btcsuite/btcd/btcec/v2"
    "golang.org/x/crypto/ripemd160"

    "btc-go/random"
)

type Result struct {
    PrivKey string
    Hash160 []byte
    Count   uint64
}

func main() {
    targetInput := flag.String("target", "801db3f6", "Target Hash160 prefix (hex)")
    numWorkers := flag.Int("t", 4, "Jumlah thread (worker) yang digunakan")
    flag.Parse()

    if *numWorkers <= 0 {
        *numWorkers = 1
    }

    targetHex := *targetInput
    targetBytes, err := hex.DecodeString(targetHex)
    if err != nil {
        fmt.Printf("Error: Target hex tidak valid (%v)\n", err)
        return
    }

    difficulty := 1.0
    for i := 0; i < len(targetBytes); i++ {
        difficulty *= 256.0
    }

    totalRange := uint64(1 << 31) 

    fmt.Printf("Searching for Hash160 starting with: %s\n", targetHex)
    fmt.Printf("Running with %d threads (Continuous Mode)...\n", *numWorkers)
    fmt.Printf("Search Space Range: 0x80000000 - 0xFFFFFFFF\n")
    fmt.Printf("Total Search Space: %d unique keys\n", totalRange)
    fmt.Printf("Target Difficulty: 1 in %.0f keys\n", difficulty)
    fmt.Println("-------------------------------------------------------------")

    var totalCounter uint64 = 0
    var foundCounter uint64 = 0

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
            fmt.Printf("Found Count    : %d\n", atomic.AddUint64(&foundCounter, 1))
            fmt.Printf("Total Attempts : %d keys\n", res.Count)
            fmt.Printf("Time Taken     : %s\n", elapsed.Round(time.Millisecond))
            fmt.Printf("Keys/second    : %.2f\n", keysPerSec)
            fmt.Println("-------------------------------------------------------------")
            fmt.Printf("PrivKey : %s\n", res.PrivKey)
            fmt.Printf("Hash160 : %x\n", res.Hash160)
            fmt.Println("-------------------------------------------------------------")
            fmt.Printf("Continuing search...\n")
        }
    }()

    // Memulai Worker
    for i := 0; i < *numWorkers; i++ {
        go func(workerID int) {
            localRng := random.NewHybrid(uint32(workerID) + uint32(time.Now().UnixNano()))
            
            ripemd160Hasher := ripemd160.New()

            for {
                select {
                case <-stopChan:
                    return
                default:
                    currentCount := atomic.AddUint64(&totalCounter, 1)
                    combined := localRng.CombineAllHex()
                    fullHex := strings.Repeat("0", 46) + combined

                    privKeyBytes, err := hex.DecodeString(fullHex)
                    if err != nil {
                        continue
                    }

                    // Proses ECDSA Public Key
                    _, pubKey := btcec.PrivKeyFromBytes(privKeyBytes)
                    pubKeyBytes := pubKey.SerializeCompressed()

                    // Hash: SHA256 -> RIPEMD160
                    sha256Hash := sha256.Sum256(pubKeyBytes)

                    ripemd160Hasher.Reset()
                    ripemd160Hasher.Write(sha256Hash[:])
                    hash160 := ripemd160Hasher.Sum(nil)

                    if bytes.HasPrefix(hash160, targetBytes) {
                        resultChan <- Result{
                            PrivKey: fullHex,
                            Hash160: hash160,
                            Count:   currentCount,
                        }
                    }

                    // Progress report
                    if workerID == 0 && currentCount%100000 == 0 {
                        percentage := (float64(currentCount) / float64(totalRange)) * 100
                        fmt.Printf("\rSearched %d keys (%.4f%% of range)...", currentCount, percentage)
                    }
                }
            }
        }(i)
    }

    // Menunggu sinyal stop (Ctrl+C)
    <-sigChan
    fmt.Println("\n\nStopping search...")
    close(stopChan)
    
    time.Sleep(500 * time.Millisecond)
    
    finalCount := atomic.LoadUint64(&totalCounter)
    finalFound := atomic.LoadUint64(&foundCounter)
    elapsed := time.Since(start)
    
    fmt.Printf("Total keys scanned: %d\n", finalCount)
    fmt.Printf("Total matches found: %d\n", finalFound)
    fmt.Printf("Average speed: %.2f keys/sec\n", float64(finalCount)/elapsed.Seconds())
}