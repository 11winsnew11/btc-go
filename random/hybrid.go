package random

import "fmt"

type Hybrid struct {
	rng    *Xorshift32
	seqPos uint32
}

func NewHybrid(seed uint32) *Hybrid {
	initialPos := (seed & 0x02FFFFFF) + 0xf0000000

	return &Hybrid{
		rng:    New(seed),
		seqPos: initialPos,
	}
}

func (h *Hybrid) Gen8DigitHex() string {
	current := h.seqPos
	jump := h.rng.Next()

	nextPos := ((h.seqPos - 0xf1000000 + jump) & 0x02FFFFFF) + 0xf1000000

	h.seqPos = nextPos
	return fmt.Sprintf("%08x", current)
}

func (h *Hybrid) CombineAllHex() string {
	part1 := h.Gen8DigitHex()
	part2 := "0000000000"
	return part1 + part2
}
