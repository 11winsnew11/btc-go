package main

import (
    "crypto/sha256"
    "encoding/hex"
    "flag"
    "fmt"
    "os"
    "os/signal"
    "sync/atomic"
    "syscall"
    "time"

    "github.com/btcsuite/btcd/btcec/v2"
    "golang.org/x/crypto/ripemd160"

    "btc-go/mod"      
    "btc-go/random"
)

type Result struct {
    PrivKey string
    Hash160 []byte
    Count   uint64
    Analysis mod.AnalysisResult 
}

func main() {
    targetHex2 := "bf7413e8df4e7a34ce" 
    numWorkers := flag.Int("t", 4, "Jumlah thread (worker) yang digunakan")
    flag.Parse()

    if *numWorkers <= 0 {
        *numWorkers = 1
    }

    _, err := hex.DecodeString(targetHex2)
    if err != nil {
        fmt.Printf("Error: Target hex2 tidak valid (%v)\n", err)
        return
    }

    totalRange := uint64(1 << 31)

    fmt.Printf("Searching for Hash160 matching criteria...\n")
    fmt.Printf("Target Comparison (Hex2): %s\n", targetHex2)
    fmt.Printf("Criteria: BitSimilarity 0.55-0.57, XorEntropy 3.1699\n")
    fmt.Printf("Running with %d threads (Continuous Mode)...\n", *numWorkers)
    fmt.Printf("Search Space Range: 0x80000000 - 0xFFFFFFFF\n")
    fmt.Println("-------------------------------------------------------------")

    var totalCounter uint64 = 0
    var foundCounter uint64 = 0

    resultChan := make(chan Result, 100)
    stopChan := make(chan struct{})
    start := time.Now()
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

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
            fmt.Printf("PrivKey        : %s\n", res.PrivKey)
            fmt.Printf("Hash160 (Hex1) : %x\n", res.Hash160[:9]) 
            fmt.Printf("Target  (Hex2) : %s\n", targetHex2)
            fmt.Println("-------------------------------------------------------------")
            fmt.Printf("Bit Similarity : %.4f\n", res.Analysis.BitSimilarity)
            fmt.Printf("XOR Entropy    : %.4f\n", res.Analysis.XorEntropy)
            fmt.Printf("Visual Diff    : %s\n", res.Analysis.VisualDiff)
            fmt.Println("-------------------------------------------------------------")
            fmt.Printf("Continuing search...\n")
        }
    }()

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
                    fullHex := "0000000000000000000000000000000000000000000000" + combined 

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
                    hex1 := hex.EncodeToString(hash160[:9])
                    analyzer := mod.NewHexAnalyzer(hex1, targetHex2, "worker_check")
                    analysis := analyzer.Process()
                    isSimilarityMatch := analysis.BitSimilarity >= 0.56 && analysis.BitSimilarity <= 0.57
                    isEntropyMatch := analysis.XorEntropy == 3.1699 

                    if isSimilarityMatch && isEntropyMatch {
                        resultChan <- Result{
                            PrivKey:  fullHex,
                            Hash160:  hash160,
                            Count:    currentCount,
                            Analysis: analysis,
                        }
                    }

                    if workerID == 0 && currentCount%100000 == 0 {
                        percentage := (float64(currentCount) / float64(totalRange)) * 100
                        fmt.Printf("\rSearched %d keys (%.4f%% of range)...", currentCount, percentage)
                    }
                }
            }
        }(i)
    }

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