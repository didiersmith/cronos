package utils

import (
	"math/big"
	"strconv"
)

func BigIntToFloat(x *big.Int) float64 {
	if x == nil {
		return 0
	}
	y, _ := new(big.Float).SetInt(x).Float64()
	return y
}

func FloatToBigInt(f float64) *big.Int {
	y, _ := big.NewFloat(f).Int(new(big.Int))
	return y
}

func StringToBigInt(s string) *big.Int {
	y, _ := new(big.Int).SetString(s, 10)
	return y
}

func Atob(s string) byte {
	i, _ := strconv.Atoi(s)
	return byte(i)
}

func Atoi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

// P1LN = (2*a^2*d*(d+c)^2)
// P1LD = (a*(d+c)*(x-r)+(a*r+c)*t)^2
// P1RN = (2*a^3*d*(d+c)^2*((d+c)*(x-r)+t))
// P1RD = (a*(d+c)*(x-r)+(a*r+c)*t)^3
// P2LN = -(2*b^2*f*(p+f)^2)
// P2LD = (b*(p+f)*(x-r)+p*t)^2
// P2RN = (2*b^3*f*(p+f)^3*(x-r))
// P2RD = (b*(p+f)*(x-r)+p*t)^3
