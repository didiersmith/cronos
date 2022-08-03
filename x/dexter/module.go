package dexter

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	// this line is used by starport scaffolding # 1

	"github.com/gorilla/mux"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/spf13/cobra"

	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/libs/log"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/crypto-org-chain/cronos/x/dexter/contracts/chicken_lite"
	hansel_lite "github.com/crypto-org-chain/cronos/x/dexter/contracts/hansel_search_lite"
	uniswap_pair "github.com/crypto-org-chain/cronos/x/dexter/contracts/uniswap_pair_lite"
	"github.com/crypto-org-chain/cronos/x/dexter/keeper"
	strategy "github.com/crypto-org-chain/cronos/x/dexter/strategy"
	"github.com/crypto-org-chain/cronos/x/dexter/utils"

	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	evmtypes "github.com/tharsis/ethermint/x/evm/types"
	// this line is used by starport scaffolding # ibc/module/import
)

var (
	_ module.AppModule      = AppModule{}
	_ module.AppModuleBasic = AppModuleBasic{}
	// this line is used by starport scaffolding # ibc/module/interface
)

const (
	ExperimentalFlag = "unsafe-experimental"
)

var (
	ownerAddr        = common.HexToAddress("0x1fb4820c368EFA3282e696CA9AAed9C3Cade2340")
	gunAddr          = common.HexToAddress("0x0E22c54094b4F3D393511F2118FA1F4894c33BAD")
	hanselSearchAddr = common.HexToAddress("0xAF6ef138e7939Becd038B0129D506F42A2f99D8D")
	chickenAddr      = common.HexToAddress("0xbcD38b64d05b40b380a4066f77664563aFFAE151")

	nullAddr           = common.HexToAddress("0x0000000000000000000000000000000000000000")
	syncEventTopic     = common.FromHex("0x1c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1")
	swapEventTopic     = common.FromHex("0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822")
	poolGetReservesAbi = uniswap_pair.GetReserves()
)

// ----------------------------------------------------------------------------
// AppModuleBasic
// ----------------------------------------------------------------------------

// AppModuleBasic implements the AppModuleBasic interface for the capability module.
type AppModuleBasic struct {
}

func NewAppModuleBasic() AppModuleBasic {
	return AppModuleBasic{}
}

// AddModuleInitFlags implements servertypes.ModuleInitFlags interface.
func AddModuleInitFlags(startCmd *cobra.Command) {
	startCmd.Flags().Bool(ExperimentalFlag, false, "Start the node with experimental features")
}

// Name returns the capability module's name.
func (AppModuleBasic) Name() string {
	return "Dexter"
}

func (AppModuleBasic) RegisterCodec(cdc *codec.LegacyAmino) {
}

func (AppModuleBasic) RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {
}

// RegisterInterfaces registers the module's interface types
func (a AppModuleBasic) RegisterInterfaces(reg cdctypes.InterfaceRegistry) {
}

// DefaultGenesis returns the capability module's default genesis state.
func (AppModuleBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	return nil
}

// ValidateGenesis performs genesis state validation for the capability module.
func (AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, config client.TxEncodingConfig, bz json.RawMessage) error {
	return nil
}

// RegisterRESTRoutes registers the capability module's REST service handlers.
func (AppModuleBasic) RegisterRESTRoutes(clientCtx client.Context, rtr *mux.Router) {
}

// RegisterGRPCGatewayRoutes registers the gRPC Gateway routes for the module.
func (AppModuleBasic) RegisterGRPCGatewayRoutes(clientCtx client.Context, mux *runtime.ServeMux) {
}

// GetTxCmd returns the capability module's root tx command.
func (a AppModuleBasic) GetTxCmd() *cobra.Command {
	return nil
}

// GetQueryCmd returns the capability module's root query command.
func (AppModuleBasic) GetQueryCmd() *cobra.Command {
	return nil
}

// ----------------------------------------------------------------------------
// AppModule
// ----------------------------------------------------------------------------

// AppModule implements the AppModule interface for the capability module.
type AppModule struct {
	AppModuleBasic
	keeper          *keeper.Keeper
	InTxChan        chan *evmtypes.MsgEthereumTx
	PermUpdaterChan chan *strategy.Reserves
	Log             log.Logger
	ContextInit     bool
}

func NewAppModule(keeper *keeper.Keeper, logger log.Logger) AppModule {
	logger.Info("NewAppModule")
	am := &AppModule{
		AppModuleBasic:  NewAppModuleBasic(),
		keeper:          keeper,
		InTxChan:        make(chan *evmtypes.MsgEthereumTx, 32),
		PermUpdaterChan: make(chan *strategy.Reserves, 1024),
		Log:             logger,
	}

	go am.processIncomingTxs()
	go am.runPermUpdater()
	go am.runRailgun()
	return *am
}

// Name returns the capability module's name.
func (am AppModule) Name() string {
	return am.AppModuleBasic.Name()
}

// Route returns the capability module's message routing key.
func (am AppModule) Route() sdk.Route {
	return sdk.NewRoute("dexter", NewHandler(am.keeper))
}

// QuerierRoute returns the capability module's query routing key.
func (AppModule) QuerierRoute() string { return "dexter" }

// LegacyQuerierHandler returns the capability module's Querier.
func (am AppModule) LegacyQuerierHandler(legacyQuerierCdc *codec.LegacyAmino) sdk.Querier {
	return nil
}

// RegisterServices registers a GRPC query service to respond to the
// module-specific GRPC queries.
func (am AppModule) RegisterServices(cfg module.Configurator) {
}

// RegisterInvariants registers the capability module's invariants.
func (am AppModule) RegisterInvariants(_ sdk.InvariantRegistry) {}

// InitGenesis performs the capability module's genesis initialization It returns
// no validator updates.
func (am AppModule) InitGenesis(ctx sdk.Context, cdc codec.JSONCodec, gs json.RawMessage) []abci.ValidatorUpdate {
	return nil
}

// ExportGenesis returns the capability module's exported genesis state as raw JSON bytes.
func (am AppModule) ExportGenesis(ctx sdk.Context, cdc codec.JSONCodec) json.RawMessage {
	return nil
}

// ConsensusVersion implements AppModule/ConsensusVersion.
func (AppModule) ConsensusVersion() uint64 { return 1 }

// BeginBlock executes all ABCI BeginBlock logic respective to the capability module.
func (am AppModule) BeginBlock(ctx sdk.Context, _ abci.RequestBeginBlock) {
	am.keeper.SetLastCtx(&ctx)
	if am.keeper.ContextInit {
		return
	}
	edgePools := make(map[strategy.EdgeKey][]common.Address)
	for _, s := range am.keeper.Strategies() {
		pairs := s.GetInterestedPairs()
		for pairAddr, _ := range pairs {
			pairInfo, ok := am.keeper.GetPoolInfo(&pairAddr)
			if !ok {
				am.Log.Info("Could not find pairInfo for interested pair", "addr", pairAddr)
				continue
			}
			token0, token1 := pairInfo.Tokens[0], pairInfo.Tokens[1]
			reserve0, reserve1 := am.getReserves(&pairAddr)
			// am.Log.Info("Gotten reserves", "pair", pairAddr, "r0", reserve0, "r1", reserve1)
			r := map[common.Address]*big.Int{token0: reserve0, token1: reserve1}
			am.keeper.SetPoolInfo(&pairAddr, &strategy.PoolInfo{
				Tokens:       pairInfo.Tokens,
				Reserves:     r,
				FeeNumerator: pairInfo.FeeNumerator,
				LastUpdate:   time.Now(),
			})
			edgeKey := strategy.MakeEdgeKey(token0, token1)
			if pools, ok := edgePools[edgeKey]; ok {
				edgePools[edgeKey] = append(pools, pairAddr)
			} else {
				edgePools[edgeKey] = []common.Address{pairAddr}
			}
		}
		am.Log.Info("Set all pairs info", "pairs", len(pairs))
	}
	for _, s := range am.keeper.Strategies() {
		s.SetPoolsInfo(am.keeper.GetAllPoolsInfo())
		s.SetEdgePools(edgePools)
		s.Start()
	}
	am.keeper.ContextInit = true
}

// EndBlock executes all ABCI EndBlock logic respective to the capability module. It
// returns no validator updates.
func (am AppModule) EndBlock(ctx sdk.Context, _ abci.RequestEndBlock) []abci.ValidatorUpdate {
	return []abci.ValidatorUpdate{}
}

func (am *AppModule) runPermUpdater() {
	for {
		rl := <-am.PermUpdaterChan
		if len(am.PermUpdaterChan) > 64 {
			am.Log.Error("PermUpdaterChan filling up!", "len", len(am.PermUpdaterChan))
		}
		currentInfo, ok := am.keeper.GetPoolInfo(&rl.PoolAddr)
		if !ok {
			am.Log.Error("Could not find pool in poolsInfo", "poolAddr", rl.PoolAddr)
			continue
		}
		r := make(map[common.Address]*big.Int)
		r[currentInfo.Tokens[0]] = rl.Reserve0
		r[currentInfo.Tokens[1]] = rl.Reserve1
		/*
			newPoolInfo := &strategy.PoolInfo{
				Tokens:       currentInfo.Tokens,
				Reserves:     r,
				FeeNumerator: currentInfo.FeeNumerator,
				Type:         currentInfo.Type,
				LastUpdate:   time.Now(),
			}
			am.keeper.SetPoolInfo(&rl.PoolAddr, newPoolInfo)
		*/
		u := strategy.PoolUpdate{
			Addr:     rl.PoolAddr,
			Reserves: r,
			Time:     time.Now(),
		}
		stateUpdate := strategy.StateUpdate{
			PermUpdates: map[common.Address]*strategy.PoolUpdate{
				rl.PoolAddr: &u,
			},
		}
		for _, s := range am.keeper.Strategies() {
			s.ProcessStateUpdates(stateUpdate)
		}
		// am.Log.Info("Perm updated pool reserves",
		// "poolAddr", rl.PoolAddr, "reserve0", rl.Reserve0, "reserve1", rl.Reserve1)
	}
}

func (am *AppModule) runRailgun() {
	for {
		select {
		case p := <-am.keeper.RailgunChan():
			p.Log.RecordTime(strategy.RailgunReceived)
			go am.prepAndFirePlan(p)
		}
	}
}

func (am *AppModule) processIncomingTxs() {
	for {
		tx := <-am.InTxChan
		start := time.Now()
		am.Log.Info("Dexter received tx", "hash", tx.Hash, "startTime", start)
		if am.keeper.LastCtx() == nil {
			am.Log.Info("Nil lastCtx, continuing")
			continue
		}
		signers := tx.GetSigners()
		if len(signers) == 0 {
			am.Log.Error("Could not get signers for tx", "hash", tx.Hash)
			continue
		}

		// Create and execute go-ethereum tx in the evm
		txE := tx.AsTransaction()
		txWTL := strategy.TxWithTimeLog{txE, strategy.NewTimeLog(start)}
		var from common.Address
		copy(from[:], signers[0].Bytes())
		txM := ethtypes.NewMessage(from, txE.To(), txE.Nonce(), txE.Value(), txE.Gas(),
			new(big.Int).Set(txE.GasPrice()), new(big.Int).Set(txE.GasFeeCap()),
			new(big.Int).Set(txE.GasTipCap()), txE.Data(), nil, false)
		am.Log.Info("Executing tx", "time since start", utils.PrettyDuration(time.Now().Sub(start)).String())
		txWTL.Log.RecordTime(strategy.TxExecuteStarted)
		resp, _ := am.keeper.Evm().ApplyMessage(*(am.keeper.LastCtx()), txM, nil, false)
		txWTL.Log.RecordTime(strategy.TxExecuteFinished)
		// am.Log.Info("Executed tx", "gasFeeCap", txE.GasFeeCap(), "GasTipCap", txE.GasTipCap())

		// Process logs
		txWTL.Log.RecordTime(strategy.ProcessTxStarted)
		var crumbs []hansel_lite.Breadcrumb
		var ptxUpdates []strategy.PoolUpdate
		for _, l := range resp.Logs {
			el := l.ToEthereum()
			pAddr, reserve0, reserve1 := getReservesFromSyncLog(el)
			if pAddr != nil {
				token0, token1 := am.getUniswapPairTokens(am.keeper.Evm(), pAddr)
				ptxUpdates = append(ptxUpdates, strategy.PoolUpdate{
					Addr:     *pAddr,
					Reserves: map[common.Address]*big.Int{token0: reserve0, token1: reserve1},
				})
				// am.Log.Info("Pool reserves", "poolAddr", pAddr, "reserve0", reserve0, "reserve1", reserve1)
			}
			poolAddr, amountIn0, _, _, _ := getAmountsFromSwapLog(el)
			if poolAddr != nil {
				poolInfo, ok := am.keeper.GetPoolInfo(poolAddr)
				if !ok {
					am.Log.Info("Pool info not found", "poolAddr", poolAddr)
					continue
				}
				token0, token1 := am.getUniswapPairTokens(am.keeper.Evm(), poolAddr)
				if ok := am.keeper.GetWhitelistedToken(&token0); !ok {
					continue
				}
				if ok := am.keeper.GetWhitelistedToken(&token1); !ok {
					continue
				}
				crumb := hansel_lite.Breadcrumb{
					FeeNumerator: poolInfo.FeeNumerator,
					PoolType:     uint8(poolInfo.Type),
				}
				if amountIn0.BitLen() == 0 {
					// Target goes from 1 -> 0, so we go from 0 -> 1
					crumb.TokenFrom, crumb.TokenTo = token0, token1
				} else {
					crumb.TokenFrom, crumb.TokenTo = token1, token0
				}
				copy(crumb.PoolId[:], poolAddr.Bytes())
				crumbs = append(crumbs, crumb)
			}
		}

		// Send txupdates to strategies
		ptx := &strategy.PossibleTx{
			Tx:        txE,
			StartTime: start,
			Updates:   ptxUpdates,
			Log:       make(strategy.TimeLog, len(strategy.TimingMomentLabels)),
		}
		for _, s := range am.keeper.Strategies() {
			copy(ptx.Log, txWTL.Log)
			s.ProcessPossibleTx(ptx)
		}

		// Send crumbs to hansel and chicken
		// am.Log.Info("Transaction processed", "len crumbs", len(crumbs))
		// route, profit := am.HanselFindRoute(crumbs)
		// am.HanselFindRoute(crumbs)
		// maxGas := 3.25e5
		// maxGasCost := new(big.Int).Mul(big.NewInt(int64(maxGas)), txE.GasFeeCap())
		// fmt.Printf("maxGasCost %s, profit %v\n", maxGasCost.String(), profit)
		// fmt.Printf("gasFeeCap %s, gasTipCap %v\n", txE.GasFeeCap().String(), txE.GasFeeCap().String())
		// if profit == nil || profit.Cmp(maxGasCost) != 1 {
		// 	am.Log.Info("Hansel found no profit")
		// 	continue
		// }
		// am.Log.Info("Hansel found profitable route", "profit", profit, "gasCost", maxGasCost)

		// chickenCrumbs := make([]chicken_lite.Breadcrumb, len(route))
		// for i, leg := range route {
		// 	crumb := chicken_lite.Breadcrumb{
		// 		TokenFrom:    leg.TokenFrom,
		// 		TokenTo:      leg.TokenTo,
		// 		FeeNumerator: leg.FeeNumerator,
		// 		PoolType:     leg.PoolType,
		// 	}
		// 	crumb.PoolId = common.BytesToAddress(leg.PoolId[:20])
		// 	// am.Log.Info("Profitable route", "leg i", i, "poolAddr", crumb.PoolId, "tokenFrom", leg.TokenFrom, "tokenTo", leg.TokenTo, "fee", leg.FeeNumerator)
		// 	chickenCrumbs[i] = crumb
		// }
		// plan := &strategy.Plan{
		// 	GasPrice:  txE.GasPrice(),
		// 	GasCost:   maxGasCost,
		// 	NetProfit: new(big.Int).Sub(profit, maxGasCost),
		// 	MinProfit: big.NewInt(0),
		// 	Path:      chickenCrumbs,
		// }

		// var timeLog strategy.TimeLog
		// copy(timeLog, txWTL.Log)
		// am.keeper.RailgunChan() <- &strategy.RailgunPacket{
		// 	Type:      strategy.HanselSwapLinear,
		// 	Target:    txE,
		// 	Response:  plan,
		// 	StartTime: start,
		// 	Log:       timeLog,
		// }
		// chickenArgs := &chicken_lite.ChickenArgs{
		// 	Gas:       uint64(maxGas),
		// 	GasFeeCap: txE.GasFeeCap(),
		// 	GasTipCap: txE.GasTipCap(),
		// }
		// _ = chickenArgs
		// am.prepAndFireRoute(route, profit, chickenArgs, txWTL.Log)
	}
}

func (am *AppModule) prepAndFirePlan(p *strategy.RailgunPacket) {
	// fmt.Printf("\n\nprepandFirePlan received route\n\n")
	p.Log.RecordTime(strategy.PrepAndFirePlanStarted)
	// bravado := d.strategyBravado[p.StrategyID]
	// probAdjustedPayoff := new(big.Int).Mul(p.Response.NetProfit, big.NewInt(int64(d.accuracy*bravado)))
	// failCost := new(big.Int).Mul(p.Response.GasPrice, big.NewInt(dexter.GAS_FAIL))
	// probAdjustedFailCost := new(big.Int).Mul(failCost, big.NewInt(int64(1e6-(d.accuracy*bravado))))
	// if probAdjustedPayoff.Cmp(probAdjustedFailCost) == -1 {
	// 	am.Log.Info("Trade unprofitable after adjusting for accuracy", "accuracy", d.accuracy, "bravado", bravado, "probAdjustedPayoff", dexter.BigIntToFloat(probAdjustedPayoff)/1e18, "lose", dexter.BigIntToFloat(probAdjustedFailCost)/1e18, "accuracy", d.accuracy, "bravado", bravado, "unadjusted win", dexter.BigIntToFloat(p.Response.NetProfit)/1e18, "unadjusted lose", dexter.BigIntToFloat(failCost)/1e18)
	// 	return
	// }
	if lastFiredTime, ok := am.keeper.GetGunLastFired(&gunAddr); ok && time.Now().Sub(lastFiredTime) < time.Second {
		am.Log.Info("Gun already fired, returning",
			"gun", gunAddr, "lastFired", utils.PrettyDuration(time.Now().Sub(lastFiredTime)))
		return
	}
	gasLimits := []uint64{0, 0, 3.25e5, 5.5e5, 7e5, 8e5}
	am.Log.Info("Gaslimit for tx", "len", len(p.Response.Path), "limit", gasLimits[len(p.Response.Path)])
	p.Log.RecordTime(strategy.GunSelected)
	chickenArgs := &chicken_lite.ChickenArgs{
		Crumbs:    p.Response.Path,
		Gas:       gasLimits[len(p.Response.Path)],
		GasPrice:  p.Response.GasPrice,
		GasFeeCap: p.Target.GasFeeCap(),
		GasTipCap: p.Target.GasTipCap(),
		// Gas:       p.Response.GasCost.Uint64()/p.Response.GasPrice.Uint64(),
	}
	fmt.Printf("Chicken Args: Gas %v, GasPrice %v, GasFeeCap %v, GasTipCap %v\n",
		chickenArgs.Gas, chickenArgs.GasPrice, chickenArgs.GasFeeCap, chickenArgs.GasTipCap)
	for i, leg := range p.Response.Path {
		fmt.Printf("Path: i %v, poolId %s, TokenFrom %s, tokenTo %s, FeeNumerator %s\n",
			i, leg.PoolId, leg.TokenFrom, leg.TokenTo, leg.FeeNumerator)
	}
	if len(p.Response.Path) <= 2 {
		fmt.Printf("Short route, returning\n")
		return
	}
	am.Log.Info("FIRING GUN pew pew",
		"profit", utils.BigIntToFloat(p.Response.NetProfit)/1e18,
		"lag", utils.PrettyDuration(time.Now().Sub(p.StartTime)),
		"strategy", am.keeper.Strategies()[p.StrategyID].GetName(),
		"gas", p.Response.GasPrice)
	// "total", utils.PrettyDuration(lag),
	// "mtts", utils.PrettyDuration(d.mtts[p.StrategyID]),
	txHash, err := am.createAndSendSwapLinear(chickenArgs, p.Log)
	if err != nil {
		return
	}
	am.keeper.SetWatchedTx(&txHash, &dextypes.TxSub{
		Hash:   txHash,
		Label:  "Dexter",
		Print:  true,
		Target: p.Target.Hash(),
	})
	var method [4]byte
	copy(method[:], p.Target.Data()[:4])
	fmt.Printf("Fired: %s source: %s  method: %v \n%s\n", txHash, p.Target.Hash().Hex(), method, p.Log.Format())
}

// func (am *AppModule) prepAndFireRoute(
// 	route []hansel_lite.Breadcrumb, profit *big.Int, chickenArgs *chicken_lite.ChickenArgs,
// 	timeLog strategy.TimeLog) {
// 	timeLog.RecordTime(strategy.PrepAndFirePlanStarted)
// 	chickenArgs.Crumbs = make([]chicken_lite.Breadcrumb, len(route))
// 	for i, leg := range route {
// 		crumb := chicken_lite.Breadcrumb{
// 			TokenFrom:    leg.TokenFrom,
// 			TokenTo:      leg.TokenTo,
// 			FeeNumerator: leg.FeeNumerator,
// 			PoolType:     leg.PoolType,
// 		}
// 		crumb.PoolId = common.BytesToAddress(leg.PoolId[:20])
// 		am.Log.Info("Profitable route", "leg i", i, "poolAddr", crumb.PoolId, "tokenFrom", leg.TokenFrom, "tokenTo", leg.TokenTo, "fee", leg.FeeNumerator)
// 		chickenArgs.Crumbs[i] = crumb
// 	}
// 	_, err := am.createAndSendSwapLinear(chickenArgs, timeLog)
// 	if err != nil {
// 		return
// 	}
// 	// am.Log.Info("Transaction ready to send", "bytes", txBytes)
// }

func (am *AppModule) HanselFindRoute(crumbs []hansel_lite.Breadcrumb) ([]hansel_lite.Breadcrumb, *big.Int) {
	msg := am.readOnlyMessage(&hanselSearchAddr, hansel_lite.FindRoute(crumbs))
	resp, err := am.keeper.Evm().ApplyMessage(*(am.keeper.LastCtx()), msg, nil, false)
	if err != nil {
		am.Log.Error("Hansel error", "err", err)
		return nil, nil
	}
	bestRoute, profit := hansel_lite.UnpackFindRoute(resp.Ret)
	if profit == nil {
		return nil, nil
	}
	return bestRoute, profit
}

func (am *AppModule) readOnlyMessage(toAddr *common.Address, data []byte) types.Message {
	var accessList types.AccessList
	return ethtypes.NewMessage(ownerAddr, toAddr, 0, new(big.Int), math.MaxUint64, new(big.Int), new(big.Int), new(big.Int), data, accessList, true)
}

func (am *AppModule) getReserves(pairAddr *common.Address) (*big.Int, *big.Int) {
	msg := am.readOnlyMessage(pairAddr, poolGetReservesAbi)
	result, err := am.keeper.Evm().ApplyMessage(*(am.keeper.LastCtx()), msg, nil, false)
	if err != nil {
		am.Log.Info("getReserves error", "err", err)
		return nil, nil
	}
	reserve0 := new(big.Int).SetBytes(result.Ret[:32])
	reserve1 := new(big.Int).SetBytes(result.Ret[32:64])
	if reserve0.BitLen() == 0 || reserve1.BitLen() == 0 {
		am.Log.Info("WARNING: getReserves() returned 0", "addr", pairAddr, "reserve0", reserve0, "reserve1", reserve1, "returnData", result.Ret)
	}
	return reserve0, reserve1
}

func (am *AppModule) createAndSendSwapLinear(chickenArgs *chicken_lite.ChickenArgs, timeLog strategy.TimeLog) (common.Hash, error) {
	lastCtx := am.keeper.LastCtx()
	rpcClientCtx := *am.keeper.APICtx()
	ak := am.keeper.AccountKeeper()
	_, err := rpcClientCtx.Keyring.KeyByAddress(sdk.AccAddress(gunAddr.Bytes()))
	if err != nil {
		am.Log.Error("Failed to find key in keyring", "address", gunAddr, "error", err.Error())
		return common.Hash{}, err
	}
	chainID := am.keeper.Evm().ChainID()
	var sdkFrom sdk.AccAddress = gunAddr[:]
	acc := ak.GetAccount(*lastCtx, sdkFrom)
	nonce := acc.GetSequence()
	timeLog.RecordTime(strategy.NonceLocated)
	accessList := make(ethtypes.AccessList, 0)
	inputData := chicken_lite.SwapLinear(big.NewInt(0), chickenArgs.Crumbs)
	am.Log.Info("Found keyring successfully", "address", sdkFrom, "nonce", nonce, "accessList", accessList)

	// am.Log.Info("Creating tx", "chainID", chainID, "nonce", nonce, "toAddr", &chickenAddr,
	// 	"gas", gas, "gasPrice", gasPrice, "gasFeeCap", gasFeeCap, "gasTipCap", gasTipCap, "accessList", accessList)
	msg := evmtypes.NewTx(chainID, nonce, &chickenAddr, big.NewInt(0), chickenArgs.Gas, chickenArgs.GasPrice,
		chickenArgs.GasFeeCap, chickenArgs.GasTipCap, inputData, &accessList)
	timeLog.RecordTime(strategy.ResponseTxCreated)
	msg.From = gunAddr.Hex()
	// am.Log.Info("Created tx successfully", "from", msg.From)

	signer := ethtypes.LatestSignerForChainID(chainID)
	if err := msg.Sign(signer, rpcClientCtx.Keyring); err != nil {
		am.Log.Error("failed to sign chicken tx", "error", err.Error())
		return common.Hash{}, err
	}
	timeLog.RecordTime(strategy.ResponseTxSigned)

	builder, ok := rpcClientCtx.TxConfig.NewTxBuilder().(authtx.ExtensionOptionsTxBuilder)
	if !ok {
		am.Log.Error("clientCtx.TxConfig.NewTxBuilder returns unsupported builder", "error", err.Error())
		return common.Hash{}, err
	}

	option, err := cdctypes.NewAnyWithValue(&evmtypes.ExtensionOptionsEthereumTx{})
	if err != nil {
		am.Log.Error("codectypes.NewAnyWithValue failed to pack an obvious value", "error", err.Error())
		return common.Hash{}, err
	}

	builder.SetExtensionOptions(option)
	err = builder.SetMsgs(msg)
	if err != nil {
		am.Log.Error("builder.SetMsgs failed", "error", err.Error())
	}
	// am.Log.Info("Set builder options")

	res, err := am.keeper.QueryClient().QueryClient.Params(am.keeper.CtxContext(), &evmtypes.QueryParamsRequest{})
	if err != nil {
		am.Log.Error("failed to query evm params", "error", err.Error())
		return common.Hash{}, err
	}

	txData, err := evmtypes.UnpackTxData(msg.Data)
	if err != nil {
		am.Log.Error("failed to unpack tx data", "error", err.Error())
		return common.Hash{}, err
	}

	fees := sdk.Coins{sdk.NewCoin(res.Params.EvmDenom, sdk.NewIntFromBigInt(txData.Fee()))}
	builder.SetFeeAmount(fees)
	builder.SetGasLimit(msg.GetGas())
	txEncoder := rpcClientCtx.TxConfig.TxEncoder()
	txBytes, err := txEncoder(builder.GetTx())
	if err != nil {
		am.Log.Error("failed to encode eth tx using default encoder", "error", err.Error())
		return common.Hash{}, err
	}
	txHash := msg.AsTransaction().Hash()
	msg.AsTransaction().Hash()
	// am.Log.Info("Transaction ready to send")
	timeLog.RecordTime(strategy.GunFireStarted)
	syncCtx := rpcClientCtx.WithBroadcastMode(flags.BroadcastSync)
	rsp, err := syncCtx.BroadcastTx(txBytes)
	if err != nil || rsp.Code != 0 {
		if err == nil {
			err = errors.New(rsp.RawLog)
		}
		am.Log.Error("failed to broadcast tx", "error", err.Error())
		return common.Hash{}, err
	}
	timeLog.RecordTime(strategy.GunFireComplete)
	return txHash, nil
}
