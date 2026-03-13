package main

import (
    "crypto/sha256"
    "encoding/hex"
    "flag" 
    "fmt"
    "strings"
    "sync/atomic"
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

    targetHex := "a21d8960"

    targetBytes, _ := hex.DecodeString(targetHex)

    seqRange := uint64(16)
    randomRange := uint64(16777216)
    totalRange := seqRange * randomRange

    fmt.Printf("Searching for Hash160 starting with: %s\n", targetHex)
    fmt.Printf("Running with %d threads (Full Parallel)...\n", *numWorkers)
    fmt.Printf("Total Search Space (Range): %d unique keys\n", totalRange)
    fmt.Println("-------------------------------------------------------------")

    var totalCounter uint64 = 0

    resultChan := make(chan Result, 1)
    stopChan := make(chan struct{})

    start := time.Now()

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

                    if hash160[0] == targetBytes[0] &&
                        hash160[1] == targetBytes[1] &&
                        hash160[2] == targetBytes[2] && 
                        hash160[3] == targetBytes[3] {

                        resultChan <- Result{
                            PrivKey: fullHex,
                            Hash160: hash160,
                            Count:   currentCount,
                        }
                        return
                    }

                    if workerID == 0 && currentCount%100000 == 0 {
                        percentage := (float64(currentCount) / float64(totalRange)) * 100
                        fmt.Printf("\rSearched %d / %d keys (%.4f%%)...", currentCount, totalRange, percentage)
                    }
                }
            }
        }(i)
    }

    found := <-resultChan
    close(stopChan)

    elapsed := time.Since(start)

    finalPercentage := (float64(found.Count) / float64(totalRange)) * 100

    time.Sleep(100 * time.Millisecond)
    fmt.Printf("\n\n!!! FOUND MATCH !!!\n")
    fmt.Printf("Total Attempts : %d keys\n", found.Count)
    fmt.Printf("Coverage       : %.6f%% of total range\n", finalPercentage)
    fmt.Printf("Time Taken     : %s\n", elapsed)
    fmt.Printf("Keys/second    : %.2f\n", float64(found.Count)/elapsed.Seconds())
    fmt.Println("-------------------------------------------------------------")
    fmt.Printf("PrivKey : %s\n", found.PrivKey)
    fmt.Printf("Hash160 : %x\n", found.Hash160)
    fmt.Println("-------------------------------------------------------------")
}