package hansel_lite

// abigen --pkg fish4 --abi=Fish4Abi.json
import (
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

const ContractABI = "[{\"inputs\":[{\"internalType\":\"address[]\",\"name\":\"_members\",\"type\":\"address[]\"},{\"components\":[{\"internalType\":\"address\",\"name\":\"addr\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"feeNumerator\",\"type\":\"uint256\"},{\"internalType\":\"enumHanselSearch.FactoryType\",\"name\":\"factoryType\",\"type\":\"uint8\"}],\"internalType\":\"structHanselSearch.uniswapFactoryDetails[]\",\"name\":\"_uniswapFactories\",\"type\":\"tuple[]\"},{\"internalType\":\"address\",\"name\":\"_baseToken\",\"type\":\"address\"}],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"member\",\"type\":\"address\"}],\"name\":\"addMember\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address[]\",\"name\":\"_members\",\"type\":\"address[]\"}],\"name\":\"addMembers\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"components\":[{\"internalType\":\"address\",\"name\":\"addr\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"feeNumerator\",\"type\":\"uint256\"},{\"internalType\":\"enumHanselSearch.FactoryType\",\"name\":\"factoryType\",\"type\":\"uint8\"}],\"internalType\":\"structHanselSearch.uniswapFactoryDetails[]\",\"name\":\"_uniswapFactories\",\"type\":\"tuple[]\"}],\"name\":\"addUniswapFactories\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"tokenAddress\",\"type\":\"address\"}],\"name\":\"dumpTokens\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"components\":[{\"internalType\":\"bytes32\",\"name\":\"poolId\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"tokenFrom\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"tokenTo\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"feeNumerator\",\"type\":\"uint256\"},{\"internalType\":\"enumHanselSearch.PoolType\",\"name\":\"poolType\",\"type\":\"uint8\"}],\"internalType\":\"structHanselSearch.Breadcrumb[]\",\"name\":\"crumbs\",\"type\":\"tuple[]\"}],\"name\":\"findRoute\",\"outputs\":[{\"components\":[{\"internalType\":\"bytes32\",\"name\":\"poolId\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"tokenFrom\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"tokenTo\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"feeNumerator\",\"type\":\"uint256\"},{\"internalType\":\"enumHanselSearch.PoolType\",\"name\":\"poolType\",\"type\":\"uint8\"}],\"internalType\":\"structHanselSearch.Breadcrumb[]\",\"name\":\"bestRoute\",\"type\":\"tuple[]\"},{\"internalType\":\"int256\",\"name\":\"profit\",\"type\":\"int256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"tokenAddress\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"withdrawTokens\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"

var (
	sAbi, _ = abi.JSON(strings.NewReader(ContractABI))
)

// Methods

type Breadcrumb struct {
	PoolId       [32]byte       `json:poolId`
	TokenFrom    common.Address `json:tokenFrom`
	TokenTo      common.Address `json:tokenTo`
	FeeNumerator *big.Int       `json:feeNumerator`
	PoolType     uint8          `json:poolType`
}

func FindRoute(crumbs []Breadcrumb) []byte {
	data, err := sAbi.Pack("findRoute", crumbs)
	if err != nil {
		log.Error("Error packing findRoute", "err", err)
	}
	return data
}

func UnpackFindRoute(data []byte) ([]Breadcrumb, *big.Int) {
	out, err := sAbi.Unpack("findRoute", data)
	if err != nil {
		return nil, nil
	}
	genericPath := out[0].([]struct {
		PoolId       [32]uint8      "json:\"poolId\""
		TokenFrom    common.Address "json:\"tokenFrom\""
		TokenTo      common.Address "json:\"tokenTo\""
		FeeNumerator *big.Int       "json:\"feeNumerator\""
		PoolType     uint8          "json:\"poolType\""
	})
	path := make([]Breadcrumb, len(genericPath))
	for i, c := range genericPath {
		path[i] = Breadcrumb(c)
	}
	return path, out[1].(*big.Int)
}
