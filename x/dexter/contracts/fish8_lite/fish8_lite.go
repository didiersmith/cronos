package fish8_lite

// abigen --pkg fish4 --abi=Fish4Abi.json
import (
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

const ContractABI = "[{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_balancerVault\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"_curveRegistry\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"_curveFactory\",\"type\":\"address\"},{\"internalType\":\"contractIPoolAddressesProvider\",\"name\":\"provider\",\"type\":\"address\"},{\"internalType\":\"address[]\",\"name\":\"_members\",\"type\":\"address[]\"}],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[],\"name\":\"ADDRESSES_PROVIDER\",\"outputs\":[{\"internalType\":\"contractIPoolAddressesProvider\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"POOL\",\"outputs\":[{\"internalType\":\"contractIPool\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"balanceIn\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"weightIn\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"balanceOut\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"weightOut\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"amountIn\",\"type\":\"uint256\"}],\"name\":\"_calcOutGivenIn\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"pure\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"member\",\"type\":\"address\"}],\"name\":\"addMember\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address[]\",\"name\":\"_members\",\"type\":\"address[]\"}],\"name\":\"addMembers\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"tokenAddress\",\"type\":\"address\"}],\"name\":\"dumpTokens\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"premium\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"initiator\",\"type\":\"address\"},{\"internalType\":\"bytes\",\"name\":\"params\",\"type\":\"bytes\"}],\"name\":\"executeOperation\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"contractIERC20[]\",\"name\":\"tokens\",\"type\":\"address[]\"},{\"internalType\":\"uint256[]\",\"name\":\"amounts\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256[]\",\"name\":\"feeAmounts\",\"type\":\"uint256[]\"},{\"internalType\":\"bytes\",\"name\":\"userData\",\"type\":\"bytes\"}],\"name\":\"receiveFlashLoan\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"target\",\"type\":\"bytes32\"},{\"internalType\":\"uint256\",\"name\":\"startAmountIn\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"minProfit\",\"type\":\"uint256\"},{\"components\":[{\"internalType\":\"bytes32\",\"name\":\"poolId\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"tokenFrom\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"tokenTo\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"feeNumerator\",\"type\":\"uint256\"},{\"internalType\":\"enumFish8.PoolType\",\"name\":\"poolType\",\"type\":\"uint8\"}],\"internalType\":\"structFish8.Breadcrumb[]\",\"name\":\"path\",\"type\":\"tuple[]\"},{\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"deadline\",\"type\":\"uint256\"}],\"name\":\"swapLinear\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"tokenAddress\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"withdrawTokens\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"

// "

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

func SwapLinear(targetHash common.Hash, startAmountIn, minProfit *big.Int, path []Breadcrumb, to common.Address, deadline *big.Int) []byte {
	data, err := sAbi.Pack("swapLinear", targetHash, startAmountIn, minProfit, path, to, deadline)
	if err != nil {
		log.Error("Error packing swapLinear", "err", err)
	}
	return data
}
