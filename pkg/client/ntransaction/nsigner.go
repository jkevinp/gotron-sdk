package ntransaction

type SignerImpl int

const (
	Software SignerImpl = iota
	Ledger
)
