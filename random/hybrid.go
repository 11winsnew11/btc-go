package random

import "fmt"

type Hybrid struct {
    rng    *Xorshift32 
    seqPos byte        
}

func NewHybrid(seed uint32) *Hybrid {
    return &Hybrid{
        rng:    New(seed),
        seqPos: 0xa0, 
    }
}

func (h *Hybrid) Gen2DigitHex() string {
    current := h.seqPos

    h.seqPos++
    
    if h.seqPos > 0xaf {
        h.seqPos = 0xa0
    }

    return fmt.Sprintf("%02x", current)
}

func (h *Hybrid) Gen6DigitHex() string {
    val := h.rng.Next()
    hexVal := val & 0xFFFFFF
    return fmt.Sprintf("%06x", hexVal)
}

func (h *Hybrid) CombineAllHex() string {
    part1 := h.Gen2DigitHex()
    part2 := h.Gen6DigitHex()
	part3 := "0000000000"
    return part1 + part2 + part3
}