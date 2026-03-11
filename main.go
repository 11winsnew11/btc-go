package main

import (
    "crypto/sha256"
    "encoding/hex"
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
    // Konfigurasi jumlah thread (worker)
    numWorkers := 20
    
    // Hapus inisialisasi global h, karena akan dibuat lokal per worker
    // h := random.NewHybrid(12345) 
    
    targetHex := "4990d9"
                  
    targetBytes, _ := hex.DecodeString(targetHex)
    
    fmt.Printf("Searching for Hash160 starting with: %s\n", targetHex)
    fmt.Printf("Running with %d threads (Full Parallel)...\n", numWorkers)
    fmt.Println("-------------------------------------------------------------")

    // Hapus Mutex karena tidak diperlukan lagi
    // var mu sync.Mutex 
    
    var totalCounter uint64 = 0
    
    resultChan := make(chan Result, 1)
    stopChan := make(chan struct{})

    start := time.Now()

    // Launcher Worker
    for i := 0; i < numWorkers; i++ {
        go func(workerID int) {
            // --- OPTIMASI 1: Generator Lokal per Worker ---
            localRng := random.NewHybrid(12345 + uint32(workerID))
            
            ripemd160Hasher := ripemd160.New()
            
            for {
                select {
                case <-stopChan:
                    return
                default:
                    currentCount := atomic.AddUint64(&totalCounter, 1)

                    // --- TANPA LOCK ---
                    // Langsung panggil generator lokal, tidak perlu mutex
                    combined := localRng.CombineAllHex()

                    fullHex := strings.Repeat("0", 46) + combined
                    
                    privKeyBytes, err := hex.DecodeString(fullHex)
                    if err != nil {
                        continue
                    }

                    // Generate Public Key
                    _, pubKey := btcec.PrivKeyFromBytes(privKeyBytes)
                    pubKeyBytes := pubKey.SerializeCompressed()
                    
                    // Hashing Langsung ke Hash160
                    sha256Hash := sha256.Sum256(pubKeyBytes)
                    
                    // Reset hasher sebelum dipakai ulang (penting!)
                    ripemd160Hasher.Reset()
                    ripemd160Hasher.Write(sha256Hash[:])
                    hash160 := ripemd160Hasher.Sum(nil)

                    // --- OPTIMASI: Bandingkan 4 Byte Langsung ---
                    if hash160[0] == targetBytes[0] && 
                       hash160[1] == targetBytes[1] && 
                       hash160[2] == targetBytes[2] {
                    //    hash160[3] == targetBytes[3] 
                       
                        
                        resultChan <- Result{
                            PrivKey: fullHex,
                            Hash160: hash160,
                            Count:   currentCount,
                        }
                        return
                    }

                    // Log Progress (hanya worker 0 untuk mengurangi race io)
                    if workerID == 0 && currentCount%100000 == 0 {
                         fmt.Printf("\rSearched %d keys...", currentCount)
                    }
                }
            }
        }(i)
    }

    // Tunggu hasil
    found := <-resultChan
    close(stopChan)

    elapsed := time.Since(start)
    
    time.Sleep(100 * time.Millisecond) 
    fmt.Printf("\n\n!!! FOUND MATCH !!!\n")
    fmt.Printf("Total Attempts: %d keys\n", found.Count)
    fmt.Printf("Time Taken    : %s\n", elapsed)
    fmt.Printf("Keys/second   : %.2f\n", float64(found.Count)/elapsed.Seconds()) // Tambahan metrik kecepatan
    fmt.Println("-------------------------------------------------------------")
    fmt.Printf("PrivKey : %s\n", found.PrivKey)
    fmt.Printf("Hash160 : %x\n", found.Hash160)
    fmt.Println("-------------------------------------------------------------")
}