package strategy

import (
	"container/heap"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/crypto-org-chain/cronos/x/dexter/contracts/chicken_lite"
	"github.com/crypto-org-chain/cronos/x/dexter/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/tendermint/tendermint/libs/log"
)

var (
	wcro        = common.HexToAddress("0x5c7f8a570d578ed84e63fdfa7b1ee72deae1ae23")
	usdc        = common.HexToAddress("0xc21223249ca28397b4b6541dffaecc539bff0c59")
	poolCoolOff = 2 * time.Second
)

type LinearStrategy struct {
	Name                string
	ID                  int
	RailgunChan         chan *RailgunPacket
	inPossibleTxsChan   chan *PossibleTx
	inStateUpdatesChan  chan StateUpdate
	cfg                 LinearStrategyConfig
	poolsInfo           map[common.Address]*PoolInfoFloat
	poolsInfoUpdateChan chan *PoolsInfoUpdateFloat
	interestedPairs     map[common.Address]PoolType
	edgePools           map[EdgeKey][]common.Address
	aggregatePools      map[EdgeKey]*PoolInfoFloat
	routeCache          MultiScoreRouteCache
	subStrategies       []Strategy
	gasPrice            int64
	mu                  sync.RWMutex
	logger              log.Logger
}

type LinearStrategyConfig struct {
	RoutesFileName          string
	PoolToRouteIdxsFileName string
	SelectSecondBest        bool
}

func NewLinearStrategy(name string, id int, railgun chan *RailgunPacket, logger log.Logger, cfg LinearStrategyConfig) Strategy {
	s := &LinearStrategy{
		Name:                name,
		ID:                  id,
		RailgunChan:         railgun,
		inPossibleTxsChan:   make(chan *PossibleTx, 256),
		inStateUpdatesChan:  make(chan StateUpdate, 256),
		cfg:                 cfg,
		poolsInfo:           make(map[common.Address]*PoolInfoFloat),
		poolsInfoUpdateChan: make(chan *PoolsInfoUpdateFloat, 32),
		interestedPairs:     make(map[common.Address]PoolType),
		aggregatePools:      make(map[EdgeKey]*PoolInfoFloat),
		logger:              logger,
	}
	s.loadJson()
	return s
}

func (s *LinearStrategy) SetPoolsInfo(poolsInfo map[common.Address]*PoolInfo) {
	for k, v := range poolsInfo {
		reserves := make(map[common.Address]float64)
		for a, r := range v.Reserves {
			reserves[a] = utils.BigIntToFloat(r)
		}
		poolInfo := &PoolInfoFloat{
			Tokens:         v.Tokens,
			Reserves:       reserves,
			FeeNumerator:   utils.BigIntToFloat(v.FeeNumerator),
			FeeNumeratorBI: v.FeeNumerator,
			LastUpdate:     time.Now(),
			Type:           UniswapV2Pair,
		}
		s.poolsInfo[k] = poolInfo
	}
}

func (s *LinearStrategy) SetEdgePools(edgePools map[EdgeKey][]common.Address) {
	s.edgePools = edgePools
}

func (s *LinearStrategy) SetGasPrice(gasPrice int64) {
	s.gasPrice = gasPrice
}

func (s *LinearStrategy) GetName() string {
	return s.Name
}

func (s *LinearStrategy) ProcessPossibleTx(t *PossibleTx) {
	select {
	case s.inPossibleTxsChan <- t:
	default:
	}
}

func (s *LinearStrategy) ProcessStateUpdates(u StateUpdate) {
	s.inStateUpdatesChan <- u
}

func (s *LinearStrategy) GetInterestedPairs() map[common.Address]PoolType {
	return s.interestedPairs
}

func (s *LinearStrategy) AddSubStrategy(sub Strategy) {
	s.subStrategies = append(s.subStrategies, sub)
}

func (s *LinearStrategy) Start() {
	s.aggregatePools = makeAggregatePoolsFloat(s.edgePools, s.poolsInfo, nil)
	for i := 0; i < len(ScoreTiers); i++ {
		s.routeCache.Scores[i] = s.makeScores(ScoreTiers[i])
	}
	s.logger.Info("1 usdc -> wcro", "amount", convertFloat(usdc, wcro, 1e6, s.aggregatePools))
	// fmt.Printf("1 usdc -> wcro: amount %v\n", convertFloat(usdc, wcro, 1e6, s.aggregatePools))
	go s.runStateUpdater()
	go s.runStrategy()
}

func (s *LinearStrategy) loadJson() {
	// s.log.Info("Loading routes")
	routeCacheRoutesFile, err := os.Open(s.cfg.RoutesFileName)
	if err != nil {
		// s.log.Info("Error opening routeCacheRoutes", "routeCacheRoutesFileName", s.cfg.RoutesFileName, "err", err)
		return
	}
	defer routeCacheRoutesFile.Close()
	routeCacheRoutesBytes, _ := ioutil.ReadAll(routeCacheRoutesFile)
	var routeCacheJson LegacyRouteCacheJson
	json.Unmarshal(routeCacheRoutesBytes, &(routeCacheJson.Routes))
	// s.log.Info("Loaded routes", "len", len(routeCacheJson.Routes))

	routeCachePoolToRouteIdxsFile, err := os.Open(s.cfg.PoolToRouteIdxsFileName)
	if err != nil {
		s.logger.Info("Error opening routeCachePoolToRouteIdxs", "routeCachePoolToRouteIdxsFileName", s.cfg.PoolToRouteIdxsFileName, "err", err)
		return
	}
	defer routeCachePoolToRouteIdxsFile.Close()
	routeCachePoolToRouteIdxsBytes, _ := ioutil.ReadAll(routeCachePoolToRouteIdxsFile)
	json.Unmarshal(routeCachePoolToRouteIdxsBytes, &(routeCacheJson.PoolToRouteIdxs))
	// s.logger.Info("Loaded poolToRouteIdxs", "len", len(routeCacheJson.PoolToRouteIdxs))

	routeCache := MultiScoreRouteCache{
		Routes:          make([][]*Leg, len(routeCacheJson.Routes)),
		PoolToRouteIdxs: make(map[PoolKey][][]uint),
		Scores:          make([][]float64, len(ScoreTiers)),
		LastFiredTime:   make([]time.Time, len(routeCacheJson.Routes)),
	}
	for i, routeJson := range routeCacheJson.Routes {
		route := make([]*Leg, len(routeJson))
		routeCache.LastFiredTime[i] = time.Now()
		// s.log.Info("Route", "routeJson", routeJson)
		for x, leg := range routeJson {
			poolAddr := common.HexToAddress(leg.PairAddr)
			t := UniswapV2Pair
			s.interestedPairs[poolAddr] = t
			route[x] = &Leg{
				From:     common.HexToAddress(leg.From),
				To:       common.HexToAddress(leg.To),
				PoolAddr: poolAddr,
				Type:     t,
			}
		}
		routeCache.Routes[i] = route
	}
	for strKey, routeIdxs := range routeCacheJson.PoolToRouteIdxs {
		parts := strings.Split(strKey, "_")
		key := poolKeyFromStrs(parts[0], parts[1], parts[2])
		routeCache.PoolToRouteIdxs[key] = make([][]uint, len(ScoreTiers))
		routeCache.PoolToRouteIdxs[key][0] = routeIdxs
		for i := 1; i < len(ScoreTiers); i++ {
			routeCache.PoolToRouteIdxs[key][i] = make([]uint, len(routeIdxs))
			copy(routeCache.PoolToRouteIdxs[key][i], routeIdxs)
		}
	}
	// fmt.Printf("Processed route cache: name %s, len(routes) %v, len(PoolToRouteIdxs) %v\n",
	// 	s.Name, len(routeCache.Routes), len(routeCache.PoolToRouteIdxs))
	s.logger.Info("Processed route cache", "name", s.Name, "len(routes)", len(routeCache.Routes), "len(PoolToRouteIdxs)", len(routeCache.PoolToRouteIdxs))
	s.routeCache = routeCache
}

func (s *LinearStrategy) makePoolInfoFloat(p *PoolUpdate, minChangeFraction float64) *PoolInfoFloat {
	s.mu.RLock()
	poolInfo, ok := s.poolsInfo[p.Addr]
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	reserves := make(map[common.Address]float64)
	updated := false
	for a, r := range p.Reserves {
		rf := utils.BigIntToFloat(r)
		reserves[a] = rf
		prevReserve := poolInfo.Reserves[a]
		if math.Abs(rf-prevReserve) > minChangeFraction*prevReserve {
			updated = true
		}
	}
	if !updated {
		return nil
	}
	return &PoolInfoFloat{
		Reserves:       reserves,
		Tokens:         poolInfo.Tokens,
		FeeNumerator:   poolInfo.FeeNumerator,
		FeeNumeratorBI: poolInfo.FeeNumeratorBI,
		LastUpdate:     time.Now(),
	}
}

func (s *LinearStrategy) runStateUpdater() {
	for {
		aggregatePoolUpdates := make(map[EdgeKey]*PoolInfoFloat)
		poolsInfoUpdates := make(map[common.Address]*PoolInfoFloat)
		refreshKeys := make(map[PoolKey]struct{})
		batch := StateUpdate{
			PermUpdates: make(map[common.Address]*PoolUpdate),
		}
		u := <-s.inStateUpdatesChan
		copyStateUpdate(&batch, &u)
	loop:
		for {
			select {
			case u2 := <-s.inStateUpdatesChan:
				copyStateUpdate(&batch, &u2)
			default:
				break loop
			}
		}
		for addr, update := range batch.PermUpdates {
			poolInfo := s.makePoolInfoFloat(update, 0)
			if poolInfo == nil {
				continue
			}
			poolsInfoUpdates[addr] = poolInfo
			key0 := poolKeyFromAddrs(poolInfo.Tokens[0], poolInfo.Tokens[1], addr)
			key1 := poolKeyFromAddrs(poolInfo.Tokens[1], poolInfo.Tokens[0], addr)
			refreshKeys[key0] = struct{}{}
			refreshKeys[key1] = struct{}{}
			aggKey := MakeEdgeKey(poolInfo.Tokens[0], poolInfo.Tokens[1])
			s.mu.RLock()
			aggregatePoolUpdates[aggKey] = refreshAggregatePoolFloat(aggKey, s.edgePools[aggKey], s.poolsInfo, poolsInfoUpdates)
			s.mu.RUnlock()
		}
		if len(poolsInfoUpdates) > 0 {
			update := &PoolsInfoUpdateFloat{
				PoolsInfoUpdates: poolsInfoUpdates,
			}
			// s.logger.Info("Linear State updater done computing updates", "t", utils.PrettyDuration(time.Now().Sub(start)), "queue", len(s.inStateUpdatesChan), "name", s.Name)
			s.poolsInfoUpdateChan <- update
			s.refreshScoresForPools(refreshKeys, poolsInfoUpdates)
		}
	}
}

func (s *LinearStrategy) runStrategy() {
	for {
		select {
		case update := <-s.poolsInfoUpdateChan:
			s.mu.Lock()
			for poolAddr, poolInfo := range update.PoolsInfoUpdates {
				s.poolsInfo[poolAddr] = poolInfo
			}
			for edgeKey, poolInfo := range update.AggregatePools {
				s.aggregatePools[edgeKey] = poolInfo
			}
			s.mu.Unlock()
		case p := <-s.inPossibleTxsChan:
			s.processPotentialTx(p)
		}
	}
}

func (s *LinearStrategy) getScore(route []*Leg, poolsInfoOverride map[common.Address]*PoolInfoFloat, amountIn float64) float64 {
	// score := 1.0
	// for _, leg := range route {
	// 	s.mu.RLock()
	// 	poolInfo := getPoolInfoFloat(s.poolsInfo, s.poolsInfoPending, poolsInfoOverride, leg.PoolAddr)
	// 	s.mu.RUnlock()
	// 	reserveFrom, reserveTo := poolInfo.Reserves[leg.From], poolInfo.Reserves[leg.To]
	// 	score = score * (reserveTo * poolInfo.FeeNumerator) / (reserveFrom * 1e6)
	// }
	// return score
	amountIn = convertFloat(wcro, route[0].From, amountIn, s.aggregatePools)
	amountOut := s.getRouteAmountOut(route, amountIn, poolsInfoOverride, false)
	amountOut = convertFloat(route[0].From, wcro, amountOut, s.aggregatePools)
	return amountOut
}

func (s *LinearStrategy) makeScores(amountIn float64) []float64 {
	scores := make([]float64, len(s.routeCache.Routes))
	for i, route := range s.routeCache.Routes {
		scores[i] = s.getScore(route, nil, amountIn)
	}
	return scores
}

func (s *LinearStrategy) refreshScoresForPools(
	keys map[PoolKey]struct{}, poolsInfoOverride map[common.Address]*PoolInfoFloat) {
	var allRouteIdxs []uint
	for key, _ := range keys {
		if routeIdxs, ok := s.routeCache.PoolToRouteIdxs[key]; ok {
			allRouteIdxs = append(allRouteIdxs, routeIdxs[0]...)
		}
	}
	sort.Slice(allRouteIdxs, func(a, b int) bool { return a < b })
	allRouteIdxs = uniq(allRouteIdxs)
	for _, routeIdx := range allRouteIdxs {
		route := s.routeCache.Routes[routeIdx]
		for i := 0; i < len(ScoreTiers); i++ {
			s.routeCache.Scores[i][routeIdx] = s.getScore(route, poolsInfoOverride, ScoreTiers[i])
		}
	}
}

func (s *LinearStrategy) getRouteAmountOut(route []*Leg, amountIn float64, poolsInfoOverride map[common.Address]*PoolInfoFloat, debug bool) float64 {
	var amountOut float64
	if debug {
		// s.log.Info("getRouteAmountOut", "amountIn", amountIn, "route", route)
	}
	for _, leg := range route {
		s.mu.RLock()
		poolInfo := getPoolInfoFloat(s.poolsInfo, poolsInfoOverride, leg.PoolAddr)
		s.mu.RUnlock()
		reserveFrom, reserveTo := poolInfo.Reserves[leg.From], poolInfo.Reserves[leg.To]
		amountOut = getAmountOutUniswapFloat(amountIn, reserveFrom, reserveTo, poolInfo.FeeNumerator)
		if debug {
			// s.log.Info("Leg", "amountIn", amountIn, "amountOut", amountOut, "reserveFrom", reserveFrom, "reserveTo", reserveTo, "feeNumerator", poolInfo.FeeNumerator)
		}
		amountIn = amountOut
	}
	return amountOut
}

func (s *LinearStrategy) processPotentialTx(ptx *PossibleTx) {
	ptx.Log.RecordTime(StrategyStarted)
	// start := time.Now()
	poolsInfoOverride := make(map[common.Address]*PoolInfoFloat)
	var updatedKeys []PoolKey
	for _, u := range ptx.Updates {
		poolInfo := s.makePoolInfoFloat(&u, minChangeFrac)
		if poolInfo == nil {
			continue
		}
		poolsInfoOverride[u.Addr] = poolInfo
		updatedKeys = append(updatedKeys,
			poolKeyFromAddrs(poolInfo.Tokens[0], poolInfo.Tokens[1], u.Addr),
			poolKeyFromAddrs(poolInfo.Tokens[1], poolInfo.Tokens[0], u.Addr))
	}
	var allProfitableRoutes []uint
	candidateRoutes := 0
	maxScoreTier := len(ScoreTiers)
	for _, key := range updatedKeys {
		var keyPop []uint
		keyPop, maxScoreTier = s.getProfitableRoutes(key, poolsInfoOverride, 4*time.Second, maxScoreTier)
		allProfitableRoutes = append(allProfitableRoutes, keyPop...)
		if routeIdxs, ok := s.routeCache.PoolToRouteIdxs[key]; ok {
			candidateRoutes += len(routeIdxs[0])
		}
		// profitableRoutes := s.getProfitableRoutes(key, poolsInfoOverride)
		// allProfitableRoutes = append(allProfitableRoutes, profitableRoutes...)
		// candidateRoutes += len(s.routeCache.PoolToRouteIdxs[key])
	}
	sort.Slice(allProfitableRoutes, func(a, b int) bool { return allProfitableRoutes[a] < allProfitableRoutes[b] })
	allProfitableRoutes = uniq(allProfitableRoutes)
	if len(allProfitableRoutes) == 0 {
		return
	}
	// s.log.Info("Computed route", "strategy", s.Name, "profitable", len(allProfitableRoutes), "/", candidateRoutes, "t", utils.PrettyDuration(time.Now().Sub(start)), "hash", ptx.Tx.Hash().Hex(), "gasPrice", ptx.Tx.GasPrice(), "size", ptx.Tx.Size(), "avoiding", len(ptx.AvoidPoolAddrs))
	s.logger.Info("Dexter found potential routes", "strategy", s.Name, "profitable", len(allProfitableRoutes), "/", candidateRoutes)
	// fmt.Printf("Dexter found potential routes: profitable routes %v of %v\n",
	// len(allProfitableRoutes), candidateRoutes)
	plan := s.getMostProfitablePath(allProfitableRoutes, poolsInfoOverride, ptx.Tx.GasPrice())
	if plan == nil {
		s.logger.Info("Dexter found no profit")
		return
	}
	s.routeCache.LastFiredTime[plan.RouteIdx] = time.Now()
	ptx.Log.RecordTime(StrategyFinished)
	// fmt.Printf("Dexter most profitable route: targetHash %v, amountIn %v, profit %v\n",
	// 	ptx.Tx.Hash().Hex(), utils.BigIntToFloat(plan.AmountIn)/1e18, utils.BigIntToFloat(plan.NetProfit)/1e18)
	s.logger.Info("Strategy linear final route", "strategy", s.Name, maxScoreTier, "amountIn", utils.BigIntToFloat(plan.AmountIn)/1e18, "profit", utils.BigIntToFloat(plan.NetProfit)/1e18)
	// s.log.Info("strategy_linear final route", "strategy", s.Name, "profitable", len(allProfitableRoutes), "/", candidateRoutes, "strategy time", utils.PrettyDuration(time.Now().Sub(start)), "total time", utils.PrettyDuration(time.Now().Sub(ptx.StartTime)), "hash", ptx.Tx.Hash().Hex(), "gasPrice", ptx.Tx.GasPrice(), "tier", maxScoreTier, "amountIn", utils.BigIntToFloat(plan.AmountIn)/1e18, "profit", utils.BigIntToFloat(plan.NetProfit)/1e18)
	// for i, leg := range plan.Path {
	// 	poolInfo := getPoolInfo(s.poolsInfo, poolsInfoOverride, leg.Pair)
	// 	origPoolInfo := s.poolsInfo[leg.Pair]
	// s.log.Info("Leg", "i", i, "pair", leg.Pair, "reserves", poolInfo.Reserves, "origReserves", origPoolInfo.Reserves)
	// }
	s.RailgunChan <- &RailgunPacket{
		Type:       SwapSinglePath,
		StrategyID: s.ID,
		Target:     ptx.Tx,
		Response:   plan,
		StartTime:  ptx.StartTime,
		Log:        ptx.Log,
	}
}

func (s *LinearStrategy) getProfitableRoutes(key PoolKey, poolsInfoOverride map[common.Address]*PoolInfoFloat, minAge time.Duration, maxScoreTier int) ([]uint, int) {
	var pop []uint
	now := time.Now()
	routeIdxs, ok := s.routeCache.PoolToRouteIdxs[key]
	// fmt.Printf("routeidxs %v\n", routeIdxs)
	if !ok {
		return pop, maxScoreTier
	}
	i := 0
	// outer:
	for ; i < maxScoreTier; i++ {
		h := RouteIdxHeap{s.routeCache.Scores[i], routeIdxs[i]}
		heap.Init(&h)
		for routeIdx := heap.Pop(&h).(uint); h.Len() > 0; routeIdx = heap.Pop(&h).(uint) {
			if now.Sub(s.routeCache.LastFiredTime[routeIdx]) < minAge {
				continue
			}
			route := s.routeCache.Routes[routeIdx]
			amountIn := convertFloat(wcro, route[0].From, ScoreTiers[i], s.aggregatePools)
			amountOut := s.getRouteAmountOut(route, amountIn, poolsInfoOverride, false)
			if amountOut < amountIn {
				break
			}
			pop = append(pop, routeIdx)
			// if len(pop) >= (i+1)*5 {
			// 	break outer
			// }
		}
		if len(pop) > 0 {
			break
		}
	}
	if i == maxScoreTier {
		return pop, i
	} else {
		return pop, i + 1
	}
}

// TODO: Update this to make a sorted list of candidates and select the second best if cfg.SelectSecondBest
func (s *LinearStrategy) getMostProfitablePath(routeIdxs []uint, poolsInfoOverride map[common.Address]*PoolInfoFloat, gasPrice *big.Int) *Plan {
	var maxProfit, bestAmountIn, bestGas float64
	var bestRouteIdx uint
	for _, routeIdx := range routeIdxs {
		route := s.routeCache.Routes[routeIdx]
		amountIn := s.getRouteOptimalAmountIn(route, poolsInfoOverride)
		if amountIn < 0 {
			// s.log.Info("WARNING: Negative amountIn for route", "routeIdx", routeIdx, "amountIn", amountIn)
			continue
		}
		amountOut := s.getRouteAmountOut(route, amountIn, poolsInfoOverride, false)
		if amountOut < amountIn {
			continue
		}
		profit := amountOut - amountIn
		// profit := new(big.Int).Sub(amountOut, amountIn)
		profit = convertFloat(route[0].From, wcro, profit, s.aggregatePools) // -> wcro
		gas := estimateFishGasFloat(1, len(route), gasPrice)
		netProfit := profit - gas
		// netProfitSubFailures := new(big.Int).Sub(netProfit, estimateFailureCost(gasPrice))

		// if i == len(routeIdxs)-1 {
		// 	fmt.Printf("Gas estimate for last trade: len(route) %v, gasUsed %v, gasCost %v\n",
		// 		len(route), gas/utils.BigIntToFloat(gasPrice), gas)
		// }
		if netProfit < maxProfit {
			continue
		}

		// if netProfitSubFailures.Cmp(maxProfit) == -1 {
		// 	continue
		// }
		// s.log.Info("New most profitable route", "amountIn", amountIn, "amountOut", amountOut, "profit", profit, "netProfit", netProfit, "gas", gas, "maxProfit", maxProfit, "routeIdx", routeIdx)
		maxProfit = netProfit
		bestAmountIn = amountIn
		bestGas = gas
		bestRouteIdx = routeIdx
	}

	if maxProfit == 0 {
		return nil
	}
	fmt.Printf("Best route: len(route) %v, gasUsed %v, gasCost %v, grossProfit %v, netProfit %v\n",
		len(s.routeCache.Routes[bestRouteIdx]), bestGas/utils.BigIntToFloat(gasPrice), bestGas,
		maxProfit+bestGas, maxProfit)

	// s.log.Info("Best route", "strategy", s.Name, "routeIdx", bestRouteIdx, "bestAmountIn", bestAmountIn, "bestAmountOut", bestAmountOut, "bestGas", bestGas, "maxProfit", maxProfit)
	return s.makePlan(bestRouteIdx, bestGas, bestAmountIn, maxProfit, gasPrice)
}

func (s *LinearStrategy) makePlan(routeIdx uint, gasCost, amountIn, netProfit float64, gasPrice *big.Int) *Plan {
	route := s.routeCache.Routes[routeIdx]
	minProfit := convertFloat(wcro, route[0].From, gasCost, s.aggregatePools)
	startAmountIn := convertFloat(wcro, route[0].From, startTokensInContractFloat, s.aggregatePools)
	plan := &Plan{
		GasPrice:  gasPrice,
		GasCost:   utils.FloatToBigInt(gasCost),
		NetProfit: utils.FloatToBigInt(netProfit),
		MinProfit: utils.FloatToBigInt(minProfit),
		AmountIn:  utils.FloatToBigInt(startAmountIn),
		Path:      make([]chicken_lite.Breadcrumb, len(route)),
	}
	for i, leg := range route {
		s.mu.RLock()
		poolInfo := s.poolsInfo[leg.PoolAddr] // No need to use override as we don't look up reserves
		s.mu.RUnlock()
		plan.Path[i] = chicken_lite.Breadcrumb{
			TokenFrom:    leg.From,
			TokenTo:      leg.To,
			FeeNumerator: poolInfo.FeeNumeratorBI,
			PoolType:     uint8(leg.Type),
		}
		copy(plan.Path[i].PoolId[:], leg.PoolAddr.Bytes())
	}
	return plan
}

func (s *LinearStrategy) getRouteOptimalAmountIn(route []*Leg, poolsInfoOverride map[common.Address]*PoolInfoFloat) float64 {
	s.mu.RLock()
	startPoolInfo := getPoolInfoFloat(s.poolsInfo, poolsInfoOverride, route[0].PoolAddr)
	s.mu.RUnlock()
	leftAmount, rightAmount := 0.0, 0.0
	leftAmount = startPoolInfo.Reserves[route[0].From]
	rightAmount = startPoolInfo.Reserves[route[0].To]
	r1 := startPoolInfo.FeeNumerator
	for _, leg := range route[1:] {
		s.mu.RLock()
		poolInfo := getPoolInfoFloat(s.poolsInfo, poolsInfoOverride, leg.PoolAddr)
		s.mu.RUnlock()
		reserveFrom, reserveTo := poolInfo.Reserves[leg.From], poolInfo.Reserves[leg.To]
		legFee := poolInfo.FeeNumerator
		den := legFee*rightAmount/1e6 + reserveFrom
		leftAmount = leftAmount * reserveFrom / den
		rightAmount = rightAmount * reserveTo * legFee / (den * 1e6)
	}
	amountIn := math.Sqrt(rightAmount*leftAmount*r1/1e6) - leftAmount
	amountIn *= 1e6 / r1
	return amountIn
}

func (s *LinearStrategy) isHotPath(route []*Leg, now time.Time) bool {
	for _, leg := range route {
		s.mu.RLock()
		poolInfo := s.poolsInfo[leg.PoolAddr]
		s.mu.RUnlock()
		if now.Sub(poolInfo.LastUpdate) < poolCoolOff {
			// s.log.Info("Route contains hot pair, skipping", "addr", leg.PoolAddr, "LastUpdate", poolInfo.LastUpdate, "now", now)
			return true
		}
	}
	return false
}
