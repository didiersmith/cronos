package types

type TxSub struct {
	Hash   common.Hash
	Label  string
	Print  bool
	Target common.Address
}
