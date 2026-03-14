package mod

import (
    "math"
    "math/bits"
    "strconv"
    "strings"
)

type AnalysisResult struct {
    Source          string
    Hex1            string
    Hex2            string
    HammingDistance int
    BitSimilarity   float64
    XorSum          int
    XorEntropy      float64
    PatternType     string
    DiffLocation    string
    VisualDiff      string
    IsClose         int
    ByteXors        []int
}

type HexAnalyzer struct {
    hex1        string
    hex2        string
    labelSource string
    h1Padded    string
    h2Padded    string
    maxLen      int
}

func NewHexAnalyzer(hex1, hex2, labelSource string) *HexAnalyzer {
    maxLen := len(hex1)
    if len(hex2) > maxLen {
        maxLen = len(hex2)
    }

    h1Padded := hex1 + strings.Repeat("0", maxLen-len(hex1))
    h2Padded := hex2 + strings.Repeat("0", maxLen-len(hex2))

    return &HexAnalyzer{
        hex1:        hex1,
        hex2:        hex2,
        labelSource: labelSource,
        h1Padded:    h1Padded,
        h2Padded:    h2Padded,
        maxLen:      maxLen,
    }
}

func (h *HexAnalyzer) hexToInt(hStr string) []int {
    var ints []int
    for i := 0; i < len(hStr); i += 2 {
        end := i + 2
        if end > len(hStr) {
            end = len(hStr)
        }
        val, err := strconv.ParseInt(hStr[i:end], 16, 64)
        if err != nil {
            val = 0
        }
        ints = append(ints, int(val))
    }
    return ints
}

func (h *HexAnalyzer) calculateEntropy(dataList []int) float64 {
    if len(dataList) == 0 {
        return 0.0
    }

    counts := make(map[int]int)
    for _, x := range dataList {
        counts[x]++
    }

    total := float64(len(dataList))
    entropy := 0.0

    for _, count := range counts {
        p := float64(count) / total
        if p > 0 {
            entropy -= p * math.Log2(p)
        }
    }

    return math.Round(entropy*10000) / 10000
}

func (h *HexAnalyzer) detectXorPattern(xorList []int) (string, int) {
    var nonZeroXors []int
    for _, x := range xorList {
        if x != 0 {
            nonZeroXors = append(nonZeroXors, x)
        }
    }

    if len(nonZeroXors) == 0 {
        return "Identical", 0
    }

    uniqueCheck := make(map[int]bool)
    for _, v := range nonZeroXors {
        uniqueCheck[v] = true
    }
    if len(uniqueCheck) == 1 {
        return "Constant Mask", nonZeroXors[0]
    }

    if len(nonZeroXors) >= 4 {
        if nonZeroXors[0] == nonZeroXors[2] && nonZeroXors[1] == nonZeroXors[3] {
            return "Repeating Pattern", nonZeroXors[0]
        }
    }

    return "Random/Complex", 0
}

func (h *HexAnalyzer) Process() AnalysisResult {
    bytes1 := h.hexToInt(h.h1Padded)
    bytes2 := h.hexToInt(h.h2Padded)

    totalBits := len(bytes1) * 8
    totalHamming := 0
    totalXorSum := 0
    var byteDiffs []int
    var xorValues []int
    var visualMap strings.Builder

    for i := 0; i < len(bytes1); i++ {
        b1 := bytes1[i]
        b2 := bytes2[i]

        xorVal := b1 ^ b2
        hamming := bits.OnesCount8(uint8(xorVal))

        totalHamming += hamming
        totalXorSum += xorVal
        byteDiffs = append(byteDiffs, hamming)
        xorValues = append(xorValues, xorVal)

        if xorVal == 0 {
            visualMap.WriteByte('=')
        } else if hamming < 4 {
            visualMap.WriteByte('!')
        } else {
            visualMap.WriteByte('#')
        }
    }

    similarityRatio := 1.0 - (float64(totalHamming) / float64(totalBits))
    entropyScore := h.calculateEntropy(xorValues)
    patternType, _ := h.detectXorPattern(xorValues)

    nBytes := len(bytes1)
    splitPoint := nBytes / 3

    hHead, hMid, hTail := 0, 0, 0
    for i, diff := range byteDiffs {
        if i < splitPoint {
            hHead += diff
        } else if i < splitPoint*2 {
            hMid += diff
        } else {
            hTail += diff
        }
    }

    diffLocation := "Middle/Distributed"
    if hHead > hMid && hHead > hTail {
        diffLocation = "Head"
    } else if hTail > hMid && hTail > hHead {
        diffLocation = "Tail"
    }

    isClose := 0
    if similarityRatio > 0.95 || patternType == "Constant Mask" {
        isClose = 1
    }

    return AnalysisResult{
        Source:          h.labelSource,
        Hex1:            h.hex1,
        Hex2:            h.hex2,
        HammingDistance: totalHamming,
        BitSimilarity:   math.Round(similarityRatio*10000) / 10000,
        XorSum:          totalXorSum,
        XorEntropy:      entropyScore,
        PatternType:     patternType,
        DiffLocation:    diffLocation,
        VisualDiff:      visualMap.String(),
        IsClose:         isClose,
        ByteXors:        xorValues,
    }
}