package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	dexkeeper "github.com/crypto-org-chain/cronos/x/dexter/keeper"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/tendermint/tendermint/libs/log"

	"github.com/crypto-org-chain/cronos/x/cronos/types"
)

// LogProcessEvmHook is an evm hook that convert specific contract logs into native module calls
type LogProcessEvmHook struct {
	handlers     map[common.Hash]types.EvmLogHandler
	dexterKeeper *dexkeeper.Keeper
	log          log.Logger
}

func NewLogProcessEvmHook(keeper *dexkeeper.Keeper, logger log.Logger, handlers ...types.EvmLogHandler) *LogProcessEvmHook {
	handlerMap := make(map[common.Hash]types.EvmLogHandler)
	for _, handler := range handlers {
		handlerMap[handler.EventID()] = handler
	}
	return &LogProcessEvmHook{
		handlers:     handlerMap,
		dexterKeeper: keeper,
	}
}

// PostTxProcessing implements EvmHook interface
func (h LogProcessEvmHook) PostTxProcessing(ctx sdk.Context, from common.Address, to *common.Address, receipt *ethtypes.Receipt) error {
	// fmt.Println("PostTxProcessing evmhook")
	if txSub, ok := h.dexterKeeper.WatchedTx(&receipt.TxHash); ok {
		if txSub.Print {
			h.log.Info("Found watched tx", "from", from, "to", to,
				"hash", receipt.TxHash().Hex(), "label", txSub.Label, "target", txSub.Target.Hex())
		}
		switch txSub.Label {
		case "Dexter":
			if receipt.Status == uint64(1) {
				h.log.Info("SUCCESS", "tx hash", receipt.TxHash)
			} else {
				h.log.Info("FAILED", "tx hash", receipt.TxHash)
			}
		}
	}
	for _, log := range receipt.Logs {
		if len(log.Topics) == 0 {
			continue
		}
		handler, ok := h.handlers[log.Topics[0]]
		if !ok {
			continue
		}
		err := handler.Handle(ctx, log.Address, log.Data)
		if err != nil {
			return err
		}
	}
	return nil
}
