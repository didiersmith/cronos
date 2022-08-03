package dexter

import (
	"bytes"
	"math"
	"math/big"

	// this line is used by starport scaffolding # 1

	"github.com/crypto-org-chain/cronos/x/cronos/types"
	hansel_lite "github.com/crypto-org-chain/cronos/x/dexter/contracts/hansel_search_lite"
	"github.com/crypto-org-chain/cronos/x/dexter/contracts/uniswap_pair_lite"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	// this line is used by starport scaffolding # ibc/module/import
)

func getReservesFromSyncLog(l *ethtypes.Log) (*common.Address, *big.Int, *big.Int) {
	if len(l.Topics) != 1 || bytes.Compare(l.Topics[0].Bytes(), syncEventTopic) != 0 {
		return nil, nil, nil
	}
	reserve0 := new(big.Int).SetBytes(l.Data[:32])
	reserve1 := new(big.Int).SetBytes(l.Data[32:])
	return &l.Address, reserve0, reserve1
}

func getAmountsFromSwapLog(l *ethtypes.Log) (*common.Address, *big.Int, *big.Int, *big.Int, *big.Int) {
	if len(l.Topics) != 3 || bytes.Compare(l.Topics[0].Bytes(), swapEventTopic) != 0 {
		return nil, nil, nil, nil, nil
	}
	amount0In := new(big.Int).SetBytes(l.Data[:32])
	amount1In := new(big.Int).SetBytes(l.Data[32:64])
	amount0Out := new(big.Int).SetBytes(l.Data[64:96])
	amount1Out := new(big.Int).SetBytes(l.Data[96:])
	return &l.Address, amount0In, amount1In, amount0Out, amount1Out
}

func readOnlyMessage(toAddr *common.Address, data []byte) ethtypes.Message {
	return ethtypes.NewMessage(ownerAddr, toAddr, 0, new(big.Int), math.MaxUint64, new(big.Int), new(big.Int), new(big.Int), data, nil, true)
}

func (am *AppModule) getUniswapPairTokens(evm types.EvmKeeper, addr *common.Address) (common.Address, common.Address) {
	msg0 := readOnlyMessage(addr, uniswap_pair_lite.Token0())
	result0, err := am.keeper.Evm().ApplyMessage(*(am.keeper.LastCtx()), msg0, nil, false)
	if err != nil {
		am.Log.Error("token0 error", "err", err)
		return common.Address{}, common.Address{}
	}
	token0 := common.BytesToAddress(result0.Ret)
	msg1 := readOnlyMessage(addr, uniswap_pair_lite.Token1())
	result1, err := am.keeper.Evm().ApplyMessage(*(am.keeper.LastCtx()), msg1, nil, false)
	if err != nil {
		am.Log.Error("token1 error", "err", err)
		return common.Address{}, common.Address{}
	}
	token1 := common.BytesToAddress(result1.Ret)
	return token0, token1
}

func (am *AppModule) hanselFindRoutes(evm types.EvmKeeper, crumbs []hansel_lite.Breadcrumb) {
}
