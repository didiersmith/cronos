package strategy

import (
	"bytes"
	"math"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/crypto-org-chain/cronos/x/dexter/contracts/chicken_lite"
	hansel_lite "github.com/crypto-org-chain/cronos/x/dexter/contracts/hansel_search_lite"
	"github.com/crypto-org-chain/cronos/x/dexter/utils"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

var (
	startTokensIn              = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	startInFloat               = utils.BigIntToFloat(startTokensIn)
	startTokensInContract      = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	startTokensInContractFloat = utils.BigIntToFloat(startTokensInContract)
	unitIn                     = 1e19
	inCandidates               = []float64{1e19, 1e20, 1e21, 1e22, 1e23}
	halfIn                     = 5e20
	kiloIn                     = 1e21
	MaxAmountIn                = new(big.Int).Mul(big.NewInt(2547), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	minChangeFrac              = 0.00001
)

const (
	GAS_INITIAL = 30000
	// GAS_INITIAL  = 3000000
	GAS_TRANSFER          = 27000
	GAS_SWAP              = 150000
	GAS_SWAP_BALANCER     = 150000
	GAS_SWAP_CURVE        = 150000
	GAS_ESTIMATE_BALANCER = 45000 + 120000   // 165000
	GAS_ESTIMATE_CURVE    = 15*25000 + 40000 // 415000
	// GAS_INITIAL  = 0
	// GAS_TRANSFER = 0
	// GAS_SWAP     = 0
	GAS_FAIL = 300000
)

type ChickenCallType int

const (
	SwapSinglePath   ChickenCallType = iota
	HanselSwapLinear ChickenCallType = iota
)

type PoolType int

const (
	UniswapV2Pair         PoolType = iota
	BalancerWeightedPool           = iota
	BalancerStablePool             = iota
	SolidlyVolatilePool            = iota
	SolidlyStablePool              = iota
	CurveBasePlainPool             = iota
	CurveFactoryPlainPool          = iota
	CurveFactoryMetaPool           = iota
)

type TimingMoment int

const (
	TxCreated            TimingMoment = iota
	TxPoolDetected                    // Fantom
	DexterReceived                    // Fantom
	EvmStateCopyStarted               // Fantom
	EvmStateCopyFinished              // Fantom
	TxExecuteStarted
	TxExecuteFinished
	ProcessTxStarted
	TxPoolReservesUpdated // Fantom
	StrategyStarted
	StrategyFinished
	RailgunReceived
	PrepAndFirePlanStarted
	ValidatorsPredicted // Fantom
	GunSelected

	NonceLocated
	ResponseTxCreated
	ResponseTxSigned

	GunFireStarted
	GunFireComplete
)

var TimingMomentLabels = []string{
	"TxCreated              ",
	"TxPoolDetected         ",
	"DexterReceived         ",
	"EvmStateCopyStarted    ",
	"EvmStateCopyFinished   ",
	"TxExecuteStarted       ",
	"TxExecuteFinished      ",
	"ProcessTxStarted       ",
	"TxPoolReservesUpdated  ",
	"StrategyStarted        ",
	"StrategyFinished       ",
	"RailgunReceived        ",
	"PrepAndFirePlanStarted ",
	"ValidatorsPredicted    ",
	"GunSelected            ",
	"NonceLocated           ",
	"ResponseTxCreated      ",
	"ResponseTxSigned       ",
	"GunFireStarted         ",
	"GunFireComplete        ",
}

type TimeLog []time.Time

func NewTimeLog(txCreatedTime time.Time) TimeLog {
	log := make(TimeLog, len(TimingMomentLabels))
	log[TxCreated] = txCreatedTime
	return log
}

func (log TimeLog) RecordTime(moment TimingMoment) {
	log[moment] = time.Now()
}

func (log TimeLog) Format() string {
	var a []string
	prev := log[0]
	p := message.NewPrinter(language.English)
	for moment, t := range log {
		diff := t.Sub(prev)
		if diff > 200*time.Microsecond {
			a = append(a, p.Sprintf("%s: %d µs", TimingMomentLabels[moment], diff.Microseconds()))
		}
		prev = t
	}
	return strings.Join(a, "\n") + "\nTotal                  " + utils.PrettyDuration(log[GunFireComplete].Sub(log[TxCreated])).String()
}

type TxFriendlyFire struct {
	Tx       *ethtypes.Transaction
	TargetTx *ethtypes.Transaction
}

type TxWithTimeLog struct {
	Tx  *ethtypes.Transaction
	Log TimeLog
}

var ScoreTiers = []float64{10000 * 1e18, 100 * 1e18, 10 * 1e18}

type PoolKey [60]byte
type EdgeKey [40]byte
type BalPoolId [32]byte

type PossibleTx struct {
	Tx             *ethtypes.Transaction
	StartTime      time.Time
	Log            TimeLog
	Updates        []PoolUpdate
	AvoidPoolAddrs []*common.Address
}

type StateUpdate struct {
	PermUpdates map[common.Address]*PoolUpdate
}

func copyStateUpdate(to, from *StateUpdate) {
	for a, poolUpdate := range from.PermUpdates {
		to.PermUpdates[a] = poolUpdate
	}
}

// Uniswap pair reserves
type Reserves struct {
	PoolAddr common.Address
	Reserve0 *big.Int
	Reserve1 *big.Int
}

type PoolUpdate struct {
	Addr     common.Address
	Reserves map[common.Address]*big.Int
	Time     time.Time

	UnderlyingReserves map[common.Address]*big.Int // Fantom
	MetaTokenSupply    *big.Int                    // Fantom
}

type PoolInfo struct {
	Tokens       []common.Address
	Reserves     map[common.Address]*big.Int
	FeeNumerator *big.Int
	Type         PoolType
	LastUpdate   time.Time

	// Fantom
	UnderlyingTokens   []common.Address
	UnderlyingReserves map[common.Address]*big.Int
	Weights            map[common.Address]*big.Int
	Fee                *big.Int
	AmplificationParam *big.Int
	ScaleFactors       map[common.Address]*big.Int
	MetaTokenSupply    *big.Int
}

type AmountOutCacheKey struct {
	TokenIn  common.Address
	TokenOut common.Address
	AmountIn float64
}

type PoolInfoFloat struct {
	Tokens           []common.Address
	Reserves         map[common.Address]float64
	FeeNumerator     float64
	FeeNumeratorBI   *big.Int
	Type             PoolType
	AmountOutCache   map[AmountOutCacheKey]float64
	AmountOutCacheMu sync.Mutex
	LastUpdate       time.Time

	// Fantom
	UnderlyingTokens   []common.Address
	UnderlyingReserves map[common.Address]float64
	Weights            map[common.Address]float64
	Fee                float64
	AmplificationParam float64 // Stored with 1e3 precision
	ScaleFactors       map[common.Address]float64
	FeeBI              *big.Int
	MetaTokenSupply    float64
}

type PoolsInfoUpdate struct {
	PoolsInfoUpdates map[common.Address]*PoolInfo
	PoolToRouteIdxs  map[PoolKey][]uint
	AggregatePools   map[EdgeKey]*PoolInfo
}

type PoolsInfoUpdateFloat struct {
	PoolsInfoUpdates        map[common.Address]*PoolInfoFloat
	PoolsInfoPendingUpdates map[common.Address]*PoolInfoFloat
	// PoolToRouteIdxs  map[PoolKey][]uint
	AggregatePools map[EdgeKey]*PoolInfoFloat
}

type Strategy interface {
	ProcessPossibleTx(ptx *PossibleTx)
	ProcessStateUpdates(u StateUpdate)
	GetInterestedPairs() map[common.Address]PoolType
	SetPoolsInfo(poolsInfo map[common.Address]*PoolInfo)
	SetEdgePools(edgePools map[EdgeKey][]common.Address)
	SetGasPrice(gasPrice int64)
	Start()
	AddSubStrategy(Strategy)
	GetName() string
}

type Plan struct {
	AmountIn  *big.Int
	GasPrice  *big.Int
	GasCost   *big.Int
	NetProfit *big.Int
	MinProfit *big.Int
	Path      []chicken_lite.Breadcrumb
	RouteIdx  uint
	Reserves  []ReserveInfo
}

type HanselPlan struct {
	Path []hansel_lite.Breadcrumb
}

type LegacyLegJson struct {
	From         string `json:from`
	To           string `json:to`
	PairAddr     string `json:pairAddr`
	ExchangeName string `json:exchangeName`
}

type LegacyRouteCacheJson struct {
	Routes          [][]LegacyLegJson `json:routes`
	PoolToRouteIdxs map[string][]uint `json:pairToRouteIdxs`
}

type LegJson struct {
	From         string `json:from`
	To           string `json:to`
	PoolAddr     string `json:poolAddr`
	PoolId       string `json:poolId`
	ExchangeType string `json:exchangeType`
	ExchangeName string `json:exchangeName`
}

type RouteCacheJson struct {
	Routes          [][]LegJson       `json:routes`
	PoolToRouteIdxs map[string][]uint `json:pairToRouteIdxs`
}

type RouteCache struct {
	Routes          [][]*Leg
	PoolToRouteIdxs map[PoolKey][]uint
	Scores          []float64
	LastFiredTime   []time.Time
}

type MultiScoreRouteCache struct {
	Routes          [][]*Leg
	PoolToRouteIdxs map[PoolKey][][]uint // poolKey -> ScoreTier -> RouteIdx
	Scores          [][]float64          // ScoreTier -> RouteIdx -> Score
	LastFiredTime   []time.Time
}

type RouteIdxHeap struct {
	Scores    []float64
	RouteIdxs []uint
}

func (h RouteIdxHeap) Len() int           { return len(h.RouteIdxs) }
func (h RouteIdxHeap) Less(i, j int) bool { return h.Scores[h.RouteIdxs[i]] > h.Scores[h.RouteIdxs[j]] }
func (h RouteIdxHeap) Swap(i, j int)      { h.RouteIdxs[i], h.RouteIdxs[j] = h.RouteIdxs[j], h.RouteIdxs[i] }

func (h *RouteIdxHeap) Push(x interface{}) {
	h.RouteIdxs = append(h.RouteIdxs, x.(uint))
}

func (h *RouteIdxHeap) Pop() interface{} {
	n := len(h.RouteIdxs)
	ret := h.RouteIdxs[n-1]
	h.RouteIdxs = h.RouteIdxs[0 : n-1]
	return ret
}

type Leg struct {
	From     common.Address
	To       common.Address
	PoolAddr common.Address
	PoolId   BalPoolId
	Type     PoolType
}

type RailgunPacket struct {
	Type           ChickenCallType
	Target         *ethtypes.Transaction
	StrategyID     int
	Response       *Plan
	HanselResponse *HanselPlan
	StartTime      time.Time
	Log            TimeLog
}

type ReserveInfo struct {
	PoolId    BalPoolId
	Type      PoolType
	Token     common.Address
	Original  *big.Int
	Predicted *big.Int
	Actual    *big.Int
}

type PoolInfoJson struct {
	Addr         string `json:addr`
	Token0       string `json:token0`
	Token1       string `json:token1`
	ExchangeName string `json:exchangeName`
	FeeNumerator int64  `json:feeNumerator`
	ExchangeType string `json:exchangeType`
}

type BalancerPoolJson struct {
	Id       string `json:id`
	Address  string `json:address`
	Amp      string `json:amp`
	SwapFee  string `json:swapFee`
	PoolType string `json:poolType`
	Name     string `json:name`
	Tokens   []struct {
		Decimals int    `json:decimals`
		Address  string `json:address`
		Weight   string `json:weight`
		Balance  string `json:balance`
	}
}

type ScoreUpdateRequest struct {
	refreshKeys              map[PoolKey]struct{}
	poolsInfoCombinedUpdates map[common.Address]*PoolInfoFloat
}

func estimateFishGasFloat(numTransfers, numSwaps int, gasPrice *big.Int) float64 {
	gas := GAS_INITIAL + (GAS_TRANSFER * numTransfers) + (GAS_SWAP * numSwaps)
	return float64(gas) * utils.BigIntToFloat(gasPrice)
}

func estimateFishGas(numTransfers, numSwaps int, gasPrice *big.Int) *big.Int {
	gas := GAS_INITIAL + (GAS_TRANSFER * numTransfers) + (GAS_SWAP * numSwaps)
	return new(big.Int).Mul(gasPrice, big.NewInt(int64(gas)))
}

func estimateFailureCost(gasPrice *big.Int) *big.Int {
	return new(big.Int).Mul(gasPrice, big.NewInt(GAS_FAIL*1))
}

func getAmountOutUniswap(amountIn, reserveIn, reserveOut, feeNumerator *big.Int) *big.Int {
	tenToSix := big.NewInt(int64(1e6))
	amountInWithFee := new(big.Int).Mul(amountIn, feeNumerator)
	numerator := new(big.Int).Mul(amountInWithFee, reserveOut)
	denominator := new(big.Int).Mul(reserveIn, tenToSix)
	denominator = denominator.Add(denominator, amountInWithFee)
	if denominator.BitLen() == 0 {
		log.Info("WARNING: getAmountOut returning 0", "reserveIn", reserveIn, "reserveOut", reserveOut, "amountIn", amountIn)
		return big.NewInt(0)
	}
	return numerator.Div(numerator, denominator)
}

func getAmountOutUniswapFloat(amountIn, reserveIn, reserveOut, feeNumerator float64) float64 {
	amountInWithFee := amountIn * feeNumerator
	numerator := amountInWithFee * reserveOut
	denominator := reserveIn*1e6 + amountInWithFee
	if denominator == 0 {
		// log.Info("WARNING: getAmountOut returning 0", "reserveIn", reserveIn, "reserveOut", reserveOut, "amountIn", amountIn)
		return 0
	}
	return numerator / denominator
}

func getAmountOutBalancer(amountIn, balanceIn, balanceOut, weightIn, weightOut, fee, scaleIn, scaleOut float64) float64 {
	amountIn = upScale(amountIn*(1-fee), scaleIn)
	base := balanceIn / (balanceIn + amountIn)
	power := math.Pow(base, weightIn/weightOut)
	return downScale(balanceOut*(1-power), scaleOut)
}

// Get the PoolInfo from poolsInfoOverride first, and poolsInfo if not found in poolsInfoOverride.
// If PoolsInfo is protected with a mutex, you must hold it while calling this.
// TODO: Check calls to this function to make sure they're mutexed.
func getPoolInfo(poolsInfo, poolsInfoOverride map[common.Address]*PoolInfo, poolAddr common.Address) *PoolInfo {
	if poolsInfoOverride != nil {
		if poolInfo, ok := poolsInfoOverride[poolAddr]; ok {
			return poolInfo
		}
	}
	poolInfo := poolsInfo[poolAddr]
	return poolInfo
}

func getPoolInfoFloat(poolsInfo, poolsInfoOverride map[common.Address]*PoolInfoFloat, poolAddr common.Address) *PoolInfoFloat {
	if poolsInfoOverride != nil {
		if poolInfo, ok := poolsInfoOverride[poolAddr]; ok {
			return poolInfo
		}
	}
	poolInfo := poolsInfo[poolAddr]
	return poolInfo
}

func uniq(sortedSlice []uint) (res []uint) {
	prev := ^uint(0) // MaxUint
	for _, v := range sortedSlice {
		if v != prev {
			res = append(res, v)
			prev = v
		}
	}
	return
}

func poolKeyFromStrs(from, to, poolAddr string) PoolKey {
	return poolKeyFromAddrs(common.HexToAddress(from), common.HexToAddress(to), common.HexToAddress(poolAddr))
}

func poolKeyFromAddrs(from, to, poolAddr common.Address) PoolKey {
	var key PoolKey
	copy(key[:20], from[:])
	copy(key[20:], to[:])
	copy(key[40:], poolAddr[:])
	return key
}

func MakeEdgeKey(a, b common.Address) (key EdgeKey) {
	if bytes.Compare(a.Bytes(), b.Bytes()) < 0 {
		copy(key[:20], a[:])
		copy(key[20:], b[:])
	} else {
		copy(key[:20], b[:])
		copy(key[20:], a[:])
	}
	return key
}

func refreshAggregatePoolFloat(key EdgeKey, pools []common.Address, poolsInfo, poolsInfoOverride map[common.Address]*PoolInfoFloat) *PoolInfoFloat {
	token0 := common.BytesToAddress(key[:20])
	token1 := common.BytesToAddress(key[20:])
	agg := &PoolInfoFloat{
		Reserves: map[common.Address]float64{token0: 0, token1: 0},
		Tokens:   []common.Address{token0, token1},
	}
	for _, poolAddr := range pools {
		pi := getPoolInfoFloat(poolsInfo, poolsInfoOverride, poolAddr)
		agg.Reserves[token0] = agg.Reserves[token0] + pi.Reserves[token0]
		agg.Reserves[token1] = agg.Reserves[token1] + pi.Reserves[token1]
	}
	return agg
}

func makeAggregatePoolsFloat(edgePools map[EdgeKey][]common.Address, poolsInfo, poolsInfoOverride map[common.Address]*PoolInfoFloat) map[EdgeKey]*PoolInfoFloat {
	aggs := make(map[EdgeKey]*PoolInfoFloat)
	for key, pools := range edgePools {
		aggs[key] = refreshAggregatePoolFloat(key, pools, poolsInfo, poolsInfoOverride)
	}
	return aggs
}

func convert(fromToken, toToken common.Address, amount *big.Int, aggregatePools map[EdgeKey]*PoolInfo) *big.Int {
	if bytes.Compare(fromToken.Bytes(), toToken.Bytes()) == 0 {
		return amount
	}
	key := MakeEdgeKey(fromToken, toToken)
	pool, ok := aggregatePools[key]
	if !ok {
		//log.Error("Could not find aggregate pool", "key", key, "len", len(aggregatePools), "fromToken", fromToken, "toToken", toToken)
		return big.NewInt(0)
	}
	x := big.NewInt(0).Mul(amount, pool.Reserves[toToken])
	return x.Div(x, pool.Reserves[fromToken])
}

func convertFloat(fromToken, toToken common.Address, amount float64, aggregatePools map[EdgeKey]*PoolInfoFloat) float64 {
	if bytes.Compare(fromToken.Bytes(), toToken.Bytes()) == 0 {
		return amount
	}
	key := MakeEdgeKey(fromToken, toToken)
	pool, ok := aggregatePools[key]
	if !ok {
		//log.Error("Could not find aggregate pool", "key", key, "len", len(aggregatePools), "fromToken", fromToken, "toToken", toToken)
		return 0
	}
	return amount * pool.Reserves[toToken] / pool.Reserves[fromToken]
}

func upScale(amount, scalingFactor float64) float64 {
	if scalingFactor == 0 {
		log.Error("Scaling factor of 0", "amount", amount, "scalingFactor", scalingFactor)
	}
	return amount * scalingFactor
}

func downScale(amount, scalingFactor float64) float64 {
	return amount / scalingFactor
}
