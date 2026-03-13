package main

import (
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
    numWorkers := flag.Int("t", 4, "Jumlah thread (worker) yang digunakan")
    flag.Parse()

    if *numWorkers <= 0 {
        *numWorkers = 1
    }

    targetHex := "cbdebfaa"

    targetBytes, _ := hex.DecodeString(targetHex)

    seqRange := uint64(16)
    randomRange := uint64(16777216)
    totalRange := seqRange * randomRange

    fmt.Printf("Searching for Hash160 starting with: %s\n", targetHex)
    fmt.Printf("Running with %d threads (Continuous Mode)...\n", *numWorkers)
    fmt.Printf("Total Search Space (Range): %d unique keys\n", totalRange)
    fmt.Println("-------------------------------------------------------------")

    var totalCounter uint64 = 0
    var foundCounter uint64 = 0

    // Channel buffer diperbesar agar worker tidak blocking jika main sedang mencetak
    resultChan := make(chan Result, 100)
    stopChan := make(chan struct{})

    start := time.Now()

    // Handler untuk Ctrl+C (Graceful Shutdown)
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

    // Goroutine untuk mencetak hasil (Consumer)
    // Ini berjalan terpisah agar worker bisa terus bekerja
    go func() {
        for res := range resultChan {
            elapsed := time.Since(start)
            
            // Hitung statistik
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
            localRng := random.NewHybrid(12345 + uint32(workerID))

            ripemd160Hasher := ripemd160.New()

            for {
                select {
                case <-stopChan:
                    return
                default:
                    currentCount := atomic.AddUint64(&totalCounter, 1)

                    combined := localRng.CombineAllHex()

                    // Logika padding tetap sama
                    fullHex := strings.Repeat("0", 46) + combined

                    privKeyBytes, err := hex.DecodeString(fullHex)
                    if err != nil {
                        continue
                    }

                    _, pubKey := btcec.PrivKeyFromBytes(privKeyBytes)
                    pubKeyBytes := pubKey.SerializeCompressed()

                    sha256Hash := sha256.Sum256(pubKeyBytes)

                    ripemd160Hasher.Reset()
                    ripemd160Hasher.Write(sha256Hash[:])
                    hash160 := ripemd160Hasher.Sum(nil)

                    // Cek kecocokan
                    if hash160[0] == targetBytes[0] &&
                        hash160[1] == targetBytes[1] &&
                        hash160[2] == targetBytes[2] &&
                        hash160[3] == targetBytes[3] {

                        // Kirim hasil ke channel, JANGAN return
                        resultChan <- Result{
                            PrivKey: fullHex,
                            Hash160: hash160,
                            Count:   currentCount,
                        }
                    }

                    // Progress report (hanya worker 0)
                    if workerID == 0 && currentCount%100000 == 0 {
                        percentage := (float64(currentCount) / float64(totalRange)) * 100
                        fmt.Printf("\rSearched %d keys (%.2f%% of range)...", currentCount, percentage)
                    }
                }
            }
        }(i)
    }

    // Menunggu sinyal stop (Ctrl+C)
    <-sigChan
    fmt.Println("\n\nStopping search...")
    close(stopChan)
    
    // Beri waktu sedikit untuk proses selesai
    time.Sleep(500 * time.Millisecond)
    
    finalCount := atomic.LoadUint64(&totalCounter)
    finalFound := atomic.LoadUint64(&foundCounter)
    elapsed := time.Since(start)
    
    fmt.Printf("Total keys scanned: %d\n", finalCount)
    fmt.Printf("Total matches found: %d\n", finalFound)
    fmt.Printf("Average speed: %.2f keys/sec\n", float64(finalCount)/elapsed.Seconds())
}