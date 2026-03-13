package random

import "fmt"

type Hybrid struct {
    rng    *Xorshift32
    seqPos uint32
}

func NewHybrid(seed uint32) *Hybrid {
    return &Hybrid{
        rng:    New(seed),
        seqPos: seed | 0x80000000, 
    }
}

func (h *Hybrid) Gen8DigitHex() string {
    current := h.seqPos
    jump := h.rng.Next()
    h.seqPos = (h.seqPos + jump) | 0x80000000
    return fmt.Sprintf("%08x", current)
}

func (h *Hybrid) CombineAllHex() string {
    part1 := h.Gen8DigitHex()
    part2 := "0000000000"
    return part1 + part2
}