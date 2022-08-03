package keeper

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/tendermint/tendermint/libs/log"

	"github.com/cosmos/cosmos-sdk/client"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/crypto-org-chain/cronos/x/cronos/types"
	strategy "github.com/crypto-org-chain/cronos/x/dexter/strategy"

	dextypes "github.com/crypto-org-chain/cronos/x/dexter/types"
	rpctypes "github.com/tharsis/ethermint/rpc/ethereum/types"
	// this line is used by starport scaffolding # ibc/keeper/import
)

var (
	bravadoAlpha = 0.75
)

type (
	Keeper struct {
		evmKeeper types.EvmKeeper
		// account keeper
		accountKeeper types.AccountKeeper
		queryClient   *rpctypes.QueryClient
		ctxContext    context.Context
		strategies    []strategy.Strategy
		railgunChan   chan *strategy.RailgunPacket
		// watchedTxChan chan *dextypes.TxSub

		root           string
		tokenWhitelist map[common.Address]struct{}
		poolsInfo      map[common.Address]*strategy.PoolInfo
		gunLastFired   map[common.Address]time.Time
		watchedTxMap   map[common.Hash]*dextypes.TxSub
		// mtts            []time.Duration
		strategyBravado []float64

		ContextInit bool
		lastCtx     *sdk.Context
		apiCtx      *client.Context
		log         log.Logger
		// this line is used by starport scaffolding # ibc/keeper/attribute
	}
)

func NewKeeper(
	evmKeeper types.EvmKeeper,
	accountKeeper types.AccountKeeper,
	root string,
	logger log.Logger,
	// this line is used by starport scaffolding # ibc/keeper/parameter
) *Keeper {
	k := &Keeper{
		evmKeeper:      evmKeeper,
		accountKeeper:  accountKeeper,
		ctxContext:     context.Background(),
		root:           root,
		tokenWhitelist: make(map[common.Address]struct{}),
		poolsInfo:      make(map[common.Address]*strategy.PoolInfo),
		gunLastFired:   make(map[common.Address]time.Time),
		watchedTxMap:   make(map[common.Hash]*dextypes.TxSub),
		ContextInit:    false,
		railgunChan:    make(chan *strategy.RailgunPacket, 8),
		// watchedTxChan:  make(chan *dextypes.TxSub, 8),
		log: logger,
	}
	k.loadJson()
	k.loadTokenWhitelist()
	k.strategies = []strategy.Strategy{
		strategy.NewLinearStrategy("Linear 2-4", 0, k.railgunChan, logger, strategy.LinearStrategyConfig{
			RoutesFileName:          root + "route_caches/routes_len2-4_100.json",
			PoolToRouteIdxsFileName: root + "route_caches/pairToRouteIdxs_len2-4_100.json",
		})}
	k.strategyBravado = make([]float64, len(k.strategies)+1)
	// k.mtts = make([]time.Duration, len(k.strategies)+1)
	for i := 0; i < len(k.strategyBravado); i++ {
		k.strategyBravado[i] = 1
		// k.mtts[i] = time.Duration(0)
	}
	return k
}

func (k *Keeper) loadJson() {
	poolsFileName := k.root + "pairs.json"
	poolsFile, err := os.Open(poolsFileName)
	if err != nil {
		k.log.Info("Error opening pools", "poolsFileName", poolsFileName, "err", err)
		return
	}
	defer poolsFile.Close()
	poolsBytes, _ := ioutil.ReadAll(poolsFile)
	var jsonPools []strategy.PoolInfoJson
	json.Unmarshal(poolsBytes, &jsonPools)
	for _, jsonPool := range jsonPools {
		poolAddr := common.HexToAddress(jsonPool.Addr)
		poolType := strategy.UniswapV2Pair
		poolTokens := make([]common.Address, 2)
		poolTokens[0] = common.HexToAddress(jsonPool.Token0)
		poolTokens[1] = common.HexToAddress(jsonPool.Token1)
		if jsonPool.ExchangeType == "SolidlyVolatilePool" {
			poolType = strategy.SolidlyVolatilePool
		} else if jsonPool.ExchangeType == "SolidlyStablePool" {
			poolType = strategy.SolidlyStablePool
		}
		k.poolsInfo[poolAddr] = &strategy.PoolInfo{
			Tokens:       poolTokens,
			FeeNumerator: big.NewInt(jsonPool.FeeNumerator),
			Type:         poolType,
		}
	}
	k.log.Info("Loaded pools", "poolsFileName", poolsFileName, "len", len(k.poolsInfo))
}

func (k *Keeper) loadTokenWhitelist() {
	whiteFilename := k.root + "whitelist.json"
	whiteFile, err := os.Open(whiteFilename)
	if err != nil {
		k.log.Info("Error opening whitelist", "whitelist filename", whiteFilename, "err", err)
		return
	}
	defer whiteFile.Close()
	whiteBytes, _ := ioutil.ReadAll(whiteFile)
	var jsonWhitelistStrs []string
	json.Unmarshal(whiteBytes, &jsonWhitelistStrs)
	for _, tokenStr := range jsonWhitelistStrs {
		tokenAddr := common.HexToAddress(tokenStr)
		k.tokenWhitelist[tokenAddr] = struct{}{}
	}
	k.log.Info("Loaded token whitelist", "whitelist filename", whiteFilename, "len", len(k.tokenWhitelist))
}

func (k *Keeper) Logger(ctx sdk.Context) log.Logger {
	return ctx.Logger().With("module", "x/Dexter")
}

func (k *Keeper) Log() log.Logger {
	return k.log
}

func (k *Keeper) Evm() types.EvmKeeper {
	return k.evmKeeper
}

func (k *Keeper) GetAllPoolsInfo() map[common.Address]*strategy.PoolInfo {
	return k.poolsInfo
}

func (k *Keeper) GetPoolInfo(addr *common.Address) (*strategy.PoolInfo, bool) {
	pi, ok := k.poolsInfo[*addr]
	return pi, ok
}

func (k *Keeper) SetPoolInfo(addr *common.Address, poolInfo *strategy.PoolInfo) {
	k.poolsInfo[*addr] = poolInfo
}

func (k *Keeper) GetGunLastFired(addr *common.Address) (time.Time, bool) {
	lastFired, ok := k.gunLastFired[*addr]
	return lastFired, ok
}

// func (k *Keeper) NewWatchedTx(txHash *common.Hash) {
// 	k.watchedTxs[*txHash] = "Dexter tx"
// }

// func (k *Keeper) WatchedTxs(txHash *common.Hash) (string, bool) {
// 	str, ok := k.watchedTxs[*txHash]
// 	// k.log.Info("Getting token from whitelist", "addr", addr, "tok", tok, "ok", ok)
// 	return str, ok
// }

func (k *Keeper) GetStrategyBravado(idx uint64) float64 {
	brav := k.strategyBravado[idx]
	return brav
}

func (k *Keeper) SetStrategyBravado(idx uint64, txSuccess bool) {
	if txSuccess {
		k.strategyBravado[idx] = k.strategyBravado[idx]*bravadoAlpha + (1 - bravadoAlpha)
	} else {
		k.strategyBravado[idx] = k.strategyBravado[idx] * bravadoAlpha
	}
}

func (k *Keeper) GetWhitelistedToken(addr *common.Address) bool {
	_, ok := k.tokenWhitelist[*addr]
	// k.log.Info("Getting token from whitelist", "addr", addr, "tok", tok, "ok", ok)
	return ok
}

func (k *Keeper) LastCtx() *sdk.Context {
	cc, _ := k.lastCtx.CacheContext()
	return &cc
}

func (k *Keeper) SetLastCtx(c *sdk.Context) {
	k.lastCtx = c
}

func (k *Keeper) APICtx() *client.Context {
	return k.apiCtx
}

func (k *Keeper) SetAPICtx(c *client.Context) {
	k.apiCtx = c
	k.queryClient = rpctypes.NewQueryClient(*c)
}

func (k *Keeper) AccountKeeper() types.AccountKeeper {
	return k.accountKeeper
}

func (k *Keeper) QueryClient() *rpctypes.QueryClient {
	return k.queryClient
}

func (k *Keeper) Strategies() []strategy.Strategy {
	return k.strategies
}

func (k *Keeper) CtxContext() context.Context {
	return k.ctxContext
}

func (k *Keeper) SetWatchedTx(hash *common.Hash, v *dextypes.TxSub) {
	k.watchedTxMap[*hash] = v
}

func (k *Keeper) WatchedTx(hash *common.Hash) (*dextypes.TxSub, bool) {
	v, err := k.watchedTxMap[*hash]
	return v, err
}

func (k *Keeper) RailgunChan() chan *strategy.RailgunPacket {
	return k.railgunChan
}
