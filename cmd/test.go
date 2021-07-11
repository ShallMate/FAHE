package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/FAHE"
)

var FAtimeall time.Duration = 0
var FAenall time.Duration = 0
var FAdeall time.Duration = 0
var FA2timeall time.Duration = 0
var FA2enall time.Duration = 0
var FA2deall time.Duration = 0

func main() {
	key, _ := FAHE.GenerateKey(rand.Reader, 128, 36, 6)
	key2, _ := FAHE.GenerateKey2(rand.Reader, 128, 36, 6)
	msgmax := big.NewInt(68719476736)
	var messages [1000]*big.Int

	for i := 0; i < 1000; i++ {
		messages[i], _ = rand.Int(rand.Reader, msgmax)
		fmt.Println(messages[i])
	}
	// 测试FAHE1 加解密1000次的效率
	for i := 0; i < 1000; i++ {
		fmt.Printf("FA encrypto m=%s\n", messages[i].String())
		start1 := time.Now()
		c := FAHE.FAHEnc(messages[i], key)
		cost1 := time.Since(start1)
		fmt.Printf("FA encrypto cost=[%s]\n", cost1)
		FAenall = FAenall + cost1
		start2 := time.Now()
		d := FAHE.FAHDec(c, key)
		cost2 := time.Since(start2)
		fmt.Printf("FA decrypto cost=[%s]\n", cost2)
		FAdeall = FAdeall + cost2
		cost3 := cost1 + cost2
		FAtimeall = FAtimeall + cost3
		fmt.Println("FA Decryption Result : ", d.String())
	}

	// 测试FAHE2 加解密1000次的效率
	for i := 0; i < 1000; i++ {
		fmt.Printf("FA encrypto m=%s\n", messages[i].String())
		start1 := time.Now()
		c := FAHE.FAHEnc2(messages[i], key2)
		cost1 := time.Since(start1)
		fmt.Printf("FA encrypto cost=[%s]\n", cost1)
		FA2enall = FA2enall + cost1
		start2 := time.Now()
		d := FAHE.FAHDec2(c, key2)
		cost2 := time.Since(start2)
		fmt.Printf("FA decrypto cost=[%s]\n", cost2)
		FA2deall = FA2deall + cost2
		cost3 := cost1 + cost2
		FA2timeall = FA2timeall + cost3
		fmt.Println("FA Decryption Result : ", d.String())
	}
	fmt.Printf("FA1 encrypto 1000 times cost=[%s]\n", FAenall)
	fmt.Printf("FA1 decrypto 1000 times cost=[%s]\n", FAdeall)
	fmt.Printf("FA1  1000 times all cost=[%s]\n", FAtimeall)
	fmt.Printf("FA2 encrypto 1000 times cost=[%s]\n", FA2enall)
	fmt.Printf("FA2 decrypto 1000 times cost=[%s]\n", FA2deall)
	fmt.Printf("FA2  1000 times all cost=[%s]\n", FA2timeall)

	m15 := big.NewInt(15)
	m20 := big.NewInt(20)
	// 简单测试FAHE1的一下同态性
	c15 := FAHE.FAHEnc(m15, key)
	c20 := FAHE.FAHEnc(m20, key)
	c := FAHE.HomoAdd(c15, c20)
	m35 := FAHE.FAHDec(c, key)
	fmt.Println(m35)

	// 简单测试FAHE2的一下同态性
	c15 = FAHE.FAHEnc2(m15, key2)
	c20 = FAHE.FAHEnc2(m20, key2)
	c = FAHE.HomoAdd(c15, c20)
	m35 = FAHE.FAHDec2(c, key2)
	fmt.Println(m35)
}
