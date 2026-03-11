package random

type Xorshift32 struct {
    state uint32
}

func New(seed uint32) *Xorshift32 {
    if seed == 0 {
        seed = 1 
    }
    return &Xorshift32{state: seed}
}

func (x *Xorshift32) Next() uint32 {
    s := x.state
    s ^= s << 13
    s ^= s >> 17
    s ^= s << 5
    
    x.state = s
    return s
}

func (x *Xorshift32) NextInRange(max int) int {
    if max <= 0 {
        return 0
    }
    return int(x.Next() % uint32(max))
}

func (x *Xorshift32) GetState() uint32 {
    return x.state
}