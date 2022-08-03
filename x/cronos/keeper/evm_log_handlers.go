package keeper

import (
	"fmt"
	"math/big"

	sdk "github.com/cosmos/cosmos-sdk/types"
	strategy "github.com/crypto-org-chain/cronos/x/dexter/strategy"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	gravitytypes "github.com/peggyjv/gravity-bridge/module/x/gravity/types"

	"github.com/crypto-org-chain/cronos/x/cronos/types"
)

var (
	_ types.EvmLogHandler = SendToAccountHandler{}
	_ types.EvmLogHandler = SendToEthereumHandler{}
	_ types.EvmLogHandler = SendToIbcHandler{}
	_ types.EvmLogHandler = SendCroToIbcHandler{}
	_ types.EvmLogHandler = SyncHandler{}
)

const (
	SendToAccountEventName  = "__CronosSendToAccount"
	SendToEthereumEventName = "__CronosSendToEthereum"
	SendToIbcEventName      = "__CronosSendToIbc"
	SendCroToIbcEventName   = "__CronosSendCroToIbc"
	SyncEventName           = "Sync"
)

var (
	// SendToAccountEvent represent the signature of
	// `event __CronosSendToAccount(address recipient, uint256 amount)`
	SendToAccountEvent abi.Event

	// SendToEthereumEvent represent the signature of
	// `event __CronosSendToEthereum(address recipient, uint256 amount, uint256 bridge_fee)`
	SendToEthereumEvent abi.Event

	// SendToIbcEvent represent the signature of
	// `event __CronosSendToIbc(string recipient, uint256 amount)`
	SendToIbcEvent abi.Event

	// SendCroToIbcEvent represent the signature of
	// `event __CronosSendCroToIbc(string recipient, uint256 amount)`
	SendCroToIbcEvent abi.Event

	// SyncEvent represent the signature of
	// `event Sync(uint112 reserve0, uint112 reserve1)`
	SyncEvent abi.Event
)

func init() {
	addressType, _ := abi.NewType("address", "", nil)
	uint256Type, _ := abi.NewType("uint256", "", nil)
	uint112Type, _ := abi.NewType("uint112", "", nil)
	stringType, _ := abi.NewType("string", "", nil)
	SendToAccountEvent = abi.NewEvent(
		SendToAccountEventName,
		SendToAccountEventName,
		false,
		abi.Arguments{abi.Argument{
			Name:    "recipient",
			Type:    addressType,
			Indexed: false,
		}, abi.Argument{
			Name:    "amount",
			Type:    uint256Type,
			Indexed: false,
		}},
	)
	SendToEthereumEvent = abi.NewEvent(
		SendToEthereumEventName,
		SendToEthereumEventName,
		false,
		abi.Arguments{abi.Argument{
			Name:    "recipient",
			Type:    addressType,
			Indexed: false,
		}, abi.Argument{
			Name:    "amount",
			Type:    uint256Type,
			Indexed: false,
		}, abi.Argument{
			Name:    "bridge_fee",
			Type:    uint256Type,
			Indexed: false,
		}},
	)
	SendToIbcEvent = abi.NewEvent(
		SendToIbcEventName,
		SendToIbcEventName,
		false,
		abi.Arguments{abi.Argument{
			Name:    "sender",
			Type:    addressType,
			Indexed: false,
		}, abi.Argument{
			Name:    "recipient",
			Type:    stringType,
			Indexed: false,
		}, abi.Argument{
			Name:    "amount",
			Type:    uint256Type,
			Indexed: false,
		}},
	)
	SendCroToIbcEvent = abi.NewEvent(
		SendCroToIbcEventName,
		SendCroToIbcEventName,
		false,
		abi.Arguments{abi.Argument{
			Name:    "sender",
			Type:    addressType,
			Indexed: false,
		}, abi.Argument{
			Name:    "recipient",
			Type:    stringType,
			Indexed: false,
		}, abi.Argument{
			Name:    "amount",
			Type:    uint256Type,
			Indexed: false,
		}},
	)
	SyncEvent = abi.NewEvent(
		SyncEventName,
		SyncEventName,
		false,
		abi.Arguments{abi.Argument{
			Name:    "reserve0",
			Type:    uint112Type,
			Indexed: false,
		}, abi.Argument{
			Name:    "reserve1",
			Type:    uint112Type,
			Indexed: false,
		}},
	)
}

// SendToAccountHandler handles `__CronosSendToAccount` log
type SendToAccountHandler struct {
	bankKeeper   types.BankKeeper
	cronosKeeper Keeper
}

func NewSendToAccountHandler(bankKeeper types.BankKeeper, cronosKeeper Keeper) *SendToAccountHandler {
	return &SendToAccountHandler{
		bankKeeper:   bankKeeper,
		cronosKeeper: cronosKeeper,
	}
}

func (h SendToAccountHandler) EventID() common.Hash {
	return SendToAccountEvent.ID
}

func (h SendToAccountHandler) Handle(ctx sdk.Context, contract common.Address, data []byte) error {
	unpacked, err := SendToAccountEvent.Inputs.Unpack(data)
	if err != nil {
		// log and ignore
		h.cronosKeeper.Logger(ctx).Error("log signature matches but failed to decode", "error", err)
		return nil
	}

	denom, found := h.cronosKeeper.GetDenomByContract(ctx, contract)
	if !found {
		return fmt.Errorf("contract %s is not connected to native token", contract)
	}

	contractAddr := sdk.AccAddress(contract.Bytes())
	recipient := sdk.AccAddress(unpacked[0].(common.Address).Bytes())
	coins := sdk.NewCoins(sdk.NewCoin(denom, sdk.NewIntFromBigInt(unpacked[1].(*big.Int))))
	err = h.bankKeeper.SendCoins(ctx, contractAddr, recipient, coins)
	if err != nil {
		return err
	}

	return nil
}

// SendToEthereumHandler handles `__CronosSendToEthereum` log
type SendToEthereumHandler struct {
	gravitySrv   gravitytypes.MsgServer
	cronosKeeper Keeper
}

func NewSendToEthereumHandler(gravitySrv gravitytypes.MsgServer, cronosKeeper Keeper) *SendToEthereumHandler {
	return &SendToEthereumHandler{
		gravitySrv:   gravitySrv,
		cronosKeeper: cronosKeeper,
	}
}

func (h SendToEthereumHandler) EventID() common.Hash {
	return SendToEthereumEvent.ID
}

// Handle `__CronosSendToEthereum` log only if gravity is activated.
func (h SendToEthereumHandler) Handle(ctx sdk.Context, contract common.Address, data []byte) error {
	if h.gravitySrv == nil {
		return fmt.Errorf("native action %s is not implemented", SendToEthereumEventName)
	}

	unpacked, err := SendToEthereumEvent.Inputs.Unpack(data)
	if err != nil {
		// log and ignore
		h.cronosKeeper.Logger(ctx).Info("log signature matches but failed to decode")
		return nil
	}

	denom, found := h.cronosKeeper.GetDenomByContract(ctx, contract)
	if !found {
		return fmt.Errorf("contract %s is not connected to native token", contract)
	}

	if !types.IsValidGravityDenom(denom) {
		return fmt.Errorf("the native token associated with the contract %s is not a gravity voucher", contract)
	}

	contractAddr := sdk.AccAddress(contract.Bytes())
	ethRecipient := unpacked[0].(common.Address)
	amount := sdk.NewIntFromBigInt(unpacked[1].(*big.Int))
	bridgeFee := sdk.NewIntFromBigInt(unpacked[2].(*big.Int))
	msg := gravitytypes.MsgSendToEthereum{
		Sender:            contractAddr.String(),
		EthereumRecipient: ethRecipient.Hex(),
		Amount:            sdk.NewCoin(denom, amount),
		BridgeFee:         sdk.NewCoin(denom, bridgeFee),
	}
	_, err = h.gravitySrv.SendToEthereum(sdk.WrapSDKContext(ctx), &msg)
	if err != nil {
		return err
	}
	return nil
}

// SendToIbcHandler handles `__CronosSendToIbc` log
type SendToIbcHandler struct {
	bankKeeper   types.BankKeeper
	cronosKeeper Keeper
}

func NewSendToIbcHandler(bankKeeper types.BankKeeper, cronosKeeper Keeper) *SendToIbcHandler {
	return &SendToIbcHandler{
		bankKeeper:   bankKeeper,
		cronosKeeper: cronosKeeper,
	}
}

func (h SendToIbcHandler) EventID() common.Hash {
	return SendToIbcEvent.ID
}

func (h SendToIbcHandler) Handle(ctx sdk.Context, contract common.Address, data []byte) error {
	unpacked, err := SendToIbcEvent.Inputs.Unpack(data)
	if err != nil {
		// log and ignore
		h.cronosKeeper.Logger(ctx).Info("log signature matches but failed to decode")
		return nil
	}

	denom, found := h.cronosKeeper.GetDenomByContract(ctx, contract)
	if !found {
		return fmt.Errorf("contract %s is not connected to native token", contract)
	}

	if !types.IsValidIBCDenom(denom) {
		return fmt.Errorf("the native token associated with the contract %s is not an ibc voucher", contract)
	}

	contractAddr := sdk.AccAddress(contract.Bytes())
	sender := sdk.AccAddress(unpacked[0].(common.Address).Bytes())
	recipient := unpacked[1].(string)
	amount := sdk.NewIntFromBigInt(unpacked[2].(*big.Int))
	coins := sdk.NewCoins(sdk.NewCoin(denom, amount))

	// First, transfer IBC coin to user so that he will be the refunded address if transfer fails
	if err = h.bankKeeper.SendCoins(ctx, contractAddr, sender, coins); err != nil {
		return err
	}
	// Initiate IBC transfer from sender account
	if err = h.cronosKeeper.IbcTransferCoins(ctx, sender.String(), recipient, coins); err != nil {
		return err
	}
	return nil
}

// SendCroToIbcHandler handles `__CronosSendCroToIbc` log
type SendCroToIbcHandler struct {
	bankKeeper   types.BankKeeper
	cronosKeeper Keeper
}

func NewSendCroToIbcHandler(bankKeeper types.BankKeeper, cronosKeeper Keeper) *SendCroToIbcHandler {
	return &SendCroToIbcHandler{
		bankKeeper:   bankKeeper,
		cronosKeeper: cronosKeeper,
	}
}

func (h SendCroToIbcHandler) EventID() common.Hash {
	return SendCroToIbcEvent.ID
}

func (h SendCroToIbcHandler) Handle(ctx sdk.Context, contract common.Address, data []byte) error {
	unpacked, err := SendCroToIbcEvent.Inputs.Unpack(data)
	if err != nil {
		// log and ignore
		h.cronosKeeper.Logger(ctx).Info("log signature matches but failed to decode")
		return nil
	}

	contractAddr := sdk.AccAddress(contract.Bytes())
	sender := sdk.AccAddress(unpacked[0].(common.Address).Bytes())
	recipient := unpacked[1].(string)
	amount := sdk.NewIntFromBigInt(unpacked[2].(*big.Int))
	evmDenom := h.cronosKeeper.GetEvmParams(ctx).EvmDenom
	coins := sdk.NewCoins(sdk.NewCoin(evmDenom, amount))
	// First, transfer IBC coin to user so that he will be the refunded address if transfer fails
	if err = h.bankKeeper.SendCoins(ctx, contractAddr, sender, coins); err != nil {
		return err
	}
	// Initiate IBC transfer from sender account
	if err = h.cronosKeeper.IbcTransferCoins(ctx, sender.String(), recipient, coins); err != nil {
		return err
	}
	return nil
}

// ----- Dexter sync log handler -----

// SyncHandler handles `Sync` log
type SyncHandler struct {
	dexterKeeper    Keeper
	PermUpdaterChan chan *strategy.Reserves
}

func NewSyncHandler(dexterKeeper Keeper, permUpdaterChan chan *strategy.Reserves) *SyncHandler {
	return &SyncHandler{
		dexterKeeper:    dexterKeeper,
		PermUpdaterChan: permUpdaterChan,
	}
}

func (h SyncHandler) EventID() common.Hash {
	return SyncEvent.ID
}

func (h SyncHandler) Handle(ctx sdk.Context, contractAddr common.Address, data []byte) error {
	unpacked, err := SyncEvent.Inputs.Unpack(data)
	if err != nil {
		// log and ignore
		h.dexterKeeper.Logger(ctx).Info("log signature matches but failed to decode")
		return nil
	}
	r := &strategy.Reserves{
		PoolAddr: contractAddr,
		Reserve0: unpacked[0].(*big.Int),
		Reserve1: unpacked[1].(*big.Int),
	}
	// fmt.Printf("Handling sync log: contractAddr %s, reserve0 %s, reserve1 %s\n\n", contractAddr, r.Reserve0, r.Reserve1)
	select {
	case h.PermUpdaterChan <- r:
	default:
		h.dexterKeeper.Logger(ctx).Error("PermUpdaterChan is full, dropping update")
	}
	return nil
}
