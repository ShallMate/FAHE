package FAHE

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	rand1 "math/rand"
	"strings"
)

var two = big.NewInt(2)
var zero = big.NewInt(0)
var modnum = big.NewInt(0)

func leftmove(m *big.Int, movenum int) *big.Int {
	mlen := m.BitLen()
	res := new(big.Int).SetBytes(m.Bytes())
	for i := mlen - 1; i >= 0; i-- {
		res.SetBit(res, i+movenum, res.Bit(i))
	}
	for i := 0; i < movenum; i++ {
		res.SetBit(res, i, 0)
	}
	return res
}

func rightmove(m *big.Int, movenum int) *big.Int {
	mlen := m.BitLen()
	res := big.NewInt(0)
	if mlen <= movenum {
		return res
	}
	res = res.SetBytes(m.Bytes())
	for i := 0; i < mlen-movenum; i++ {
		res.SetBit(res, i, res.Bit(i+movenum))
	}
	for i := mlen - 1; i >= mlen-movenum; i-- {
		res.SetBit(res, i, 0)
	}
	return res
}

type Key struct {
	p               *big.Int
	x               *big.Int
	rou             *big.Int
	Aerfa           *big.Int
	Msize           *big.Int
	rouaerfa        *big.Int
	twoexprouaerfa  *big.Int //FAHE1独有
	twoexpposaerfa  *big.Int //FAHE2独有
	twoexpposaerfam *big.Int //FAHE2独有
	subpos          int      // FAHE2独有,代表λ−pos
	pos             int
	roulen          int
}

// FAHE1 的秘钥生成函数
func GenerateKey(random io.Reader, bits int, msgsize int, a int) (*Key, error) {
	// α 代表最多可以做多少次同态计算
	aerfa := big.NewInt(int64(a))
	// ρ，和安全参数λ相等
	rou, _ := rand.Prime(random, bits)
	// 与计算ρ加α
	rouaerfa := new(big.Int).Add(rou, aerfa)
	// 计算 一塔
	yitalen := 2*a + bits + msgsize
	yita, _ := rand.Prime(random, yitalen)

	lgrou := big.NewInt(int64(strings.Count(rou.String(), "") - 1))
	yitasubrou := new(big.Int).Sub(yita, rou)
	y := new(big.Int).Mul(new(big.Int).Div(rou, lgrou), new(big.Int).Mul(yitasubrou, yitasubrou))
	p, _ := rand.Prime(random, yitalen)
	modnum, _ = rand.Prime(random, 256)
	X := new(big.Int).Div(new(big.Int).Exp(two, y, modnum), p)
	twoexprouaerfa := new(big.Int).Exp(two, big.NewInt(int64(bits+a)), modnum)
	//fmt.Println(twoexprouaerfa.BitLen())

	return &Key{
		p:              p,
		x:              X,
		rou:            rou,
		Aerfa:          aerfa,
		Msize:          big.NewInt(int64(msgsize)),
		rouaerfa:       rouaerfa,
		roulen:         rou.BitLen(),
		twoexprouaerfa: twoexprouaerfa,
	}, nil
}

// FAHE2 的秘钥生成函数
func GenerateKey2(random io.Reader, bits int, msgsize int, a int) (*Key, error) {
	// α 代表最多可以做多少次同态计算
	aerfa := big.NewInt(int64(a))
	// ρ = λ + α + |msize |
	rou, _ := rand.Prime(random, bits+a+msgsize)
	// 与计算ρ加α
	rouaerfa := new(big.Int).Add(rou, aerfa)
	// 计算 η = ρ + α
	yitalen := a + rou.BitLen()
	yita, _ := rand.Prime(random, yitalen)
	// 计算γ = ( ρ/lgρ · (η − ρ) ^2 )
	lgrou := big.NewInt(int64(strings.Count(rou.String(), "") - 1))
	yitasubrou := new(big.Int).Sub(yita, rou)
	y := new(big.Int).Mul(new(big.Int).Div(rou, lgrou), new(big.Int).Mul(yitasubrou, yitasubrou))
	//p和η一样长的素数
	p, _ := rand.Prime(random, yitalen)
	modnum, _ = rand.Prime(random, 256)
	X := new(big.Int).Div(new(big.Int).Exp(two, y, modnum), p)
	pos := rand1.Intn(bits)
	fmt.Println(pos)
	//预计算λ−pos
	subpos := bits - pos
	fmt.Println(subpos)
	//预计算<< (pos+|msize |+α)
	twoexpposaerfam := new(big.Int).Exp(two, big.NewInt(int64(pos+a+msgsize)), modnum)
	twoexpposaerfa := new(big.Int).Exp(two, big.NewInt(int64(pos+a)), modnum)
	return &Key{
		p:               p,
		x:               X,
		rou:             rou,
		Aerfa:           aerfa,
		Msize:           big.NewInt(int64(msgsize)),
		rouaerfa:        rouaerfa,
		roulen:          rou.BitLen(),
		twoexpposaerfam: twoexpposaerfam,
		twoexpposaerfa:  twoexpposaerfa,
		subpos:          subpos,
		pos:             pos,
	}, nil
}

//FAHE1加密
func FAHEnc(m *big.Int, key *Key) *big.Int {
	random := rand.Reader
	q, _ := rand.Int(random, key.x)
	noise, _ := rand.Prime(random, key.roulen)
	M := new(big.Int).Mul(m, key.twoexprouaerfa)
	M = M.Add(M, noise)
	//fmt.Println(M.BitLen())
	//fmt.Println(key.p.BitLen())
	n := new(big.Int).Mul(key.p, q)
	c := new(big.Int).Add(M, n)
	return c
}

//FAHE2加密
func FAHEnc2(m *big.Int, key *Key) *big.Int {
	random := rand.Reader
	q, _ := rand.Int(random, key.x)
	noise1, _ := rand.Prime(random, key.pos)
	noise2 := zero
	//fmt.Println(noise2)
	//fmt.Println(noise2.BitLen())
	//M = (noise2  (pos+|m max |+α))+(m (pos+α))+noise1
	M1 := new(big.Int).Mul(noise2, key.twoexpposaerfam)
	M2 := new(big.Int).Add(new(big.Int).Mul(m, key.twoexpposaerfa), M1)
	M := new(big.Int).Add(M2, noise1)
	//fmt.Println(M.BitLen())
	n := new(big.Int).Mul(key.p, q)
	c := new(big.Int).Add(M, n)
	return c
}

//FAHE1解密
func FAHDec(c *big.Int, key *Key) *big.Int {
	c = c.Mod(c, key.p)
	m := new(big.Int).Div(c, key.twoexprouaerfa)
	return m
}

//FAHE2解密
func FAHDec2(c *big.Int, key *Key) *big.Int {
	c = c.Mod(c, key.p)
	m := new(big.Int).Div(c, key.twoexpposaerfa)
	return m
}

func HomoAdd(c1 *big.Int, c2 *big.Int) *big.Int {
	c := new(big.Int).Add(c1, c2)
	return c
}
