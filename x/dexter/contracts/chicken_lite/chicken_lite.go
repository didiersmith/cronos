package chicken_lite

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

const ContractABI = "[{\"inputs\":[{\"internalType\":\"address[]\",\"name\":\"_members\",\"type\":\"address[]\"},{\"components\":[{\"internalType\":\"address\",\"name\":\"addr\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"feeNumerator\",\"type\":\"uint256\"}],\"internalType\":\"structChicken.uniswapFactoryDetails[]\",\"name\":\"_uniswapFactories\",\"type\":\"tuple[]\"},{\"internalType\":\"address\",\"name\":\"_baseToken\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"member\",\"type\":\"address\"}],\"name\":\"addMember\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address[]\",\"name\":\"_members\",\"type\":\"address[]\"}],\"name\":\"addMembers\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"components\":[{\"internalType\":\"address\",\"name\":\"addr\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"feeNumerator\",\"type\":\"uint256\"}],\"internalType\":\"structChicken.uniswapFactoryDetails[]\",\"name\":\"_uniswapFactories\",\"type\":\"tuple[]\"}],\"name\":\"addUniswapFactories\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"tokenAddress\",\"type\":\"address\"}],\"name\":\"dumpTokens\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"minProfit\",\"type\":\"uint256\"},{\"components\":[{\"internalType\":\"address\",\"name\":\"poolId\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"tokenFrom\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"tokenTo\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"feeNumerator\",\"type\":\"uint256\"},{\"internalType\":\"enumChicken.PoolType\",\"name\":\"poolType\",\"type\":\"uint8\"}],\"internalType\":\"structChicken.Breadcrumb[]\",\"name\":\"path\",\"type\":\"tuple[]\"}],\"name\":\"swapLinear\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"userData\",\"type\":\"bytes\"}],\"name\":\"uniswapV2Call\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"tokenAddress\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"withdrawTokens\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"

var (
	sAbi, _ = abi.JSON(strings.NewReader(ContractABI))
)

// Methods

type ChickenArgs struct {
	Crumbs    []Breadcrumb
	Gas       uint64
	GasPrice  *big.Int
	GasFeeCap *big.Int
	GasTipCap *big.Int
}

type Breadcrumb struct {
	PoolId       common.Address
	TokenFrom    common.Address
	TokenTo      common.Address
	FeeNumerator *big.Int
	PoolType     uint8
}

func SwapLinear(minProfit *big.Int, crumbs []Breadcrumb) []byte {
	data, err := sAbi.Pack("swapLinear", minProfit, crumbs)
	if err != nil {
		fmt.Printf("Error packing swapLinear")
	}
	return data
}
