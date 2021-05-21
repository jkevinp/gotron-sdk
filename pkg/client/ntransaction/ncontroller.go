package ntransaction

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"
	proto "github.com/golang/protobuf/proto"
	"github.com/jkevinp/gotron-sdk/pkg/client"
	"github.com/jkevinp/gotron-sdk/pkg/common"
	"github.com/jkevinp/gotron-sdk/pkg/keystore"
	"github.com/jkevinp/gotron-sdk/pkg/ledger"
	"github.com/jkevinp/gotron-sdk/pkg/proto/api"
	"github.com/jkevinp/gotron-sdk/pkg/proto/core"

	"golang.org/x/crypto/sha3"
)

var (
	// ErrBadTransactionParam is returned when invalid params are given to the
	// controller upon execution of a transaction.
	ErrBadTransactionParam = errors.New("transaction has bad parameters")
)

type sender struct {
	ks      *keystore.KeyStore
	account *keystore.Account
}

// Controller drives the transaction signing process
type Controller struct {
	executionError error
	resultError    error
	client         *client.GrpcClient
	tx             *core.Transaction

	privateKey      string
	edscaPrivateKey *ecdsa.PrivateKey
	Behavior        behavior
	Result          *api.Return
	Receipt         *core.TransactionInfo
}

type behavior struct {
	DryRun               bool
	ConfirmationWaitTime uint32
}

func addressFromKey(keyStr string) (key *ecdsa.PrivateKey, tronAddr string) {

	// Build the Private Key and extract the Public Key
	keyBytes, _ := hex.DecodeString(keyStr)
	key = new(ecdsa.PrivateKey)
	key.PublicKey.Curve = btcec.S256()
	key.D = new(big.Int).SetBytes(keyBytes)
	key.PublicKey.X, key.PublicKey.Y = key.PublicKey.Curve.ScalarBaseMult(keyBytes)

	// #1
	pub := append(key.X.Bytes(), key.Y.Bytes()...)

	// #2
	hash := sha3.NewLegacyKeccak256()
	hash.Write(pub)
	hashed := hash.Sum(nil)
	last20 := hashed[len(hashed)-20:]

	// #3
	addr41 := append([]byte{0x41}, last20...)

	// #4
	hash2561 := sha256.Sum256(addr41)
	hash2562 := sha256.Sum256(hash2561[:])
	checksum := hash2562[:4]

	// #5/#6
	rawAddr := append(addr41, checksum...)
	tronAddr = base58.Encode(rawAddr)
	return

}

// NewController initializes a Controller, caller can control behavior via options
func NewController(
	client *client.GrpcClient,
	privKey string,
	tx *core.Transaction,
	options ...func(*Controller),
) *Controller {

	ctrlr := &Controller{
		executionError: nil,
		resultError:    nil,
		client:         client,
		privateKey:     privKey,
		tx:             tx,
		Behavior:       behavior{false, 0},
	}

	ctrlr.edscaPrivateKey, _ = addressFromKey(privKey)

	for _, option := range options {
		option(ctrlr)
	}
	return ctrlr
}

// SignTxWithPrivKey signs the given transaction with the requested account.
func (C *Controller) SignTxWithPrivKey(pk *ecdsa.PrivateKey, tx *core.Transaction) (*core.Transaction, error) {
	// Look up the key to sign with and abort if it cannot be found

	rawData, err := proto.Marshal(tx.GetRawData())
	if err != nil {
		return nil, err
	}
	h256h := sha256.New()
	h256h.Write(rawData)
	hash := h256h.Sum(nil)

	signature, err := crypto.Sign(hash, pk)
	if err != nil {
		return nil, err
	}
	tx.Signature = append(tx.Signature, signature)

	return tx, nil
}

func (C *Controller) signTxForSending() {
	if C.executionError != nil {
		return
	}
	signedTransaction, err := C.SignTxWithPrivKey(C.edscaPrivateKey, C.tx)
	// C.sender.ks.SignTx(*C.sender.account, C.tx)
	if err != nil {
		C.executionError = err
		return
	}
	C.tx = signedTransaction
}

func (C *Controller) hardwareSignTxForSending() {
	if C.executionError != nil {
		return
	}
	data, _ := C.GetRawData()
	signature, err := ledger.SignTx(data)
	if err != nil {
		C.executionError = err
		return
	}

	/* TODO: validate signature
	if strings.Compare(signerAddr, address.ToBech32(C.sender.account.Address)) != 0 {
		C.executionError = ErrBadTransactionParam
		errorMsg := "signature verification failed : sender address doesn't match with ledger hardware address"
		C.transactionErrors = append(C.transactionErrors, &Error{
			ErrMessage:           &errorMsg,
			TimestampOfRejection: time.Now().Unix(),
		})
		return
	}
	*/
	// add signature
	C.tx.Signature = append(C.tx.Signature, signature)
}

// TransactionHash extract hash from TX
func (C *Controller) TransactionHash() (string, error) {
	rawData, err := C.GetRawData()
	if err != nil {
		return "", err
	}
	h256h := sha256.New()
	h256h.Write(rawData)
	hash := h256h.Sum(nil)
	return common.ToHex(hash), nil
}

func (C *Controller) txConfirmation() {
	if C.executionError != nil || C.Behavior.DryRun {
		return
	}
	if C.Behavior.ConfirmationWaitTime > 0 {
		txHash, err := C.TransactionHash()
		if err != nil {
			C.executionError = fmt.Errorf("could not get tx hash")
			return
		}
		//fmt.Printf("TX hash: %s\nWaiting for confirmation....", txHash)
		start := int(C.Behavior.ConfirmationWaitTime)
		for {
			// GETTX by ID
			if txi, err := C.client.GetTransactionInfoByID(txHash); err == nil {
				// check receipt
				if txi.Result != 0 {
					C.resultError = fmt.Errorf("%s", txi.ResMessage)
				}
				// Add receipt
				C.Receipt = txi
				return
			}
			if start < 0 {
				C.executionError = fmt.Errorf("could not confirm transaction after %d seconds", C.Behavior.ConfirmationWaitTime)
				return
			}
			time.Sleep(time.Second)
			start--
		}
	} else {
		C.Receipt = &core.TransactionInfo{}
		C.Receipt.Receipt = &core.ResourceReceipt{}
	}

}

// GetResultError return result error
func (C *Controller) GetResultError() error {
	return C.resultError
}

// ExecuteTransaction is the single entrypoint to execute a plain transaction.
// Each step in transaction creation, execution probably includes a mutation
// Each becomes a no-op if executionError occurred in any previous step
func (C *Controller) ExecuteTransaction() error {
	C.signTxForSending()
	C.sendSignedTx()
	C.txConfirmation()
	return C.executionError
}

// GetRawData Byes from Transaction
func (C *Controller) GetRawData() ([]byte, error) {
	return proto.Marshal(C.tx.GetRawData())
}

func (C *Controller) sendSignedTx() {
	if C.executionError != nil || C.Behavior.DryRun {
		return
	}
	result, err := C.client.Broadcast(C.tx)
	if err != nil {
		C.executionError = err
		return
	}
	if result.Code != 0 {
		C.executionError = fmt.Errorf("bad transaction: %v", string(result.GetMessage()))
	}
	C.Result = result
}
