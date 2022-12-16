// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package eth

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
)

// PublicEthereumAPI provides an API to access Ethereum full node-related
// information.
type PublicEthereumAPI struct {
	e *Ethereum
}

// NewPublicEthereumAPI creates a new Ethereum protocol API for full nodes.
func NewPublicEthereumAPI(e *Ethereum) *PublicEthereumAPI {
	return &PublicEthereumAPI{e}
}

// Etherbase is the address that mining rewards will be send to
func (api *PublicEthereumAPI) Etherbase() (common.Address, error) {
	return api.e.Etherbase()
}

// Coinbase is the address that mining rewards will be send to (alias for Etherbase)
func (api *PublicEthereumAPI) Coinbase() (common.Address, error) {
	return api.Etherbase()
}

// Hashrate returns the POW hashrate
func (api *PublicEthereumAPI) Hashrate() hexutil.Uint64 {
	return hexutil.Uint64(api.e.Miner().HashRate())
}

// ChainId is the EIP-155 replay-protection chain id for the current ethereum chain config.
func (api *PublicEthereumAPI) ChainId() hexutil.Uint64 {
	chainID := new(big.Int)
	if config := api.e.blockchain.Config(); config.IsEIP155(api.e.blockchain.CurrentBlock().Number()) {
		chainID = config.ChainID
	}
	return (hexutil.Uint64)(chainID.Uint64())
}

// PublicMinerAPI provides an API to control the miner.
// It offers only methods that operate on data that pose no security risk when it is publicly accessible.
type PublicMinerAPI struct {
	e *Ethereum
}

// NewPublicMinerAPI create a new PublicMinerAPI instance.
func NewPublicMinerAPI(e *Ethereum) *PublicMinerAPI {
	return &PublicMinerAPI{e}
}

// Mining returns an indication if this node is currently mining.
func (api *PublicMinerAPI) Mining() bool {
	return api.e.IsMining()
}

// PrivateMinerAPI provides private RPC methods to control the miner.
// These methods can be abused by external users and must be considered insecure for use by untrusted users.
type PrivateMinerAPI struct {
	e *Ethereum
}

// NewPrivateMinerAPI create a new RPC service which controls the miner of this node.
func NewPrivateMinerAPI(e *Ethereum) *PrivateMinerAPI {
	return &PrivateMinerAPI{e: e}
}

// Start starts the miner with the given number of threads. If threads is nil,
// the number of workers started is equal to the number of logical CPUs that are
// usable by this process. If mining is already running, this method adjust the
// number of threads allowed to use and updates the minimum price required by the
// transaction pool.
func (api *PrivateMinerAPI) Start(threads *int) error {
	if threads == nil {
		return api.e.StartMining(runtime.NumCPU())
	}
	return api.e.StartMining(*threads)
}

// Stop terminates the miner, both at the consensus engine level as well as at
// the block creation level.
func (api *PrivateMinerAPI) Stop() {
	api.e.StopMining()
}

// SetExtra sets the extra data string that is included when this miner mines a block.
func (api *PrivateMinerAPI) SetExtra(extra string) (bool, error) {
	if err := api.e.Miner().SetExtra([]byte(extra)); err != nil {
		return false, err
	}
	return true, nil
}

// SetGasPrice sets the minimum accepted gas price for the miner.
func (api *PrivateMinerAPI) SetGasPrice(gasPrice hexutil.Big) bool {
	api.e.lock.Lock()
	api.e.gasPrice = (*big.Int)(&gasPrice)
	api.e.lock.Unlock()

	api.e.txPool.SetGasPrice((*big.Int)(&gasPrice))
	return true
}

// SetEtherbase sets the etherbase of the miner
func (api *PrivateMinerAPI) SetEtherbase(etherbase common.Address) bool {
	api.e.SetEtherbase(etherbase)
	return true
}

// SetRecommitInterval updates the interval for miner sealing work recommitting.
func (api *PrivateMinerAPI) SetRecommitInterval(interval int) {
	api.e.Miner().SetRecommitInterval(time.Duration(interval) * time.Millisecond)
}

// GetHashrate returns the current hashrate of the miner.
func (api *PrivateMinerAPI) GetHashrate() uint64 {
	return api.e.miner.HashRate()
}

// PrivateAdminAPI is the collection of Ethereum full node-related APIs
// exposed over the private admin endpoint.
type PrivateAdminAPI struct {
	eth *Ethereum
}

// NewPrivateAdminAPI creates a new API definition for the full node private
// admin methods of the Ethereum service.
func NewPrivateAdminAPI(eth *Ethereum) *PrivateAdminAPI {
	return &PrivateAdminAPI{eth: eth}
}

func (api *PrivateAdminAPI) NicoAdmin() (map[string]interface{}, error) {
	fmt.Println("Nico:::NicoAdmin")
	return nil, nil
}

func decodeHeaderFromRequest(encodedHeader []hexutil.Bytes) (*types.Header, error) {
	// &types.Header{
	// 		Number:      big.NewInt(1),
	// 		ParentHash:  common.HexToHash("0x27c7b2d6df69bc6c016eae2c4a7983aa6819eb9ab5748019bdbc7c2cbbbf356f"),
	// 		UncleHash:   common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
	// 		Coinbase:    common.HexToAddress("0xc0ea08a2d404d3172d2add29a45be56da40e2949"),
	// 		Root:        common.HexToHash("0x77d14e10470b5850332524f8cd6f69ad21f070ce92dca33ab2858300242ef2f1"),
	// 		TxHash:      common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
	// 		ReceiptHash: common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
	// 		Difficulty:  big.NewInt(1),
	// 		GasLimit:    4015682,
	// 		GasUsed:     0,
	// 		Time:        1488928920,
	// 		Extra:       []byte("www.bw.com"),
	// 		MixDigest:   common.HexToHash("0x3e140b0784516af5e5ec6730f2fb20cca22f32be399b9e4ad77d32541f798cd0"),
	// 		Nonce:       types.EncodeNonce(0x0000000000000000), //0x31cbccc8efea6b03f4f8e3376e1f5ffd7771e1d5
	// 	}
	fmt.Println("Nico:::decodeHeaderFromRequest")

	headerNumber := big.NewInt(0)
	if err := rlp.DecodeBytes(encodedHeader[0], headerNumber); err != nil {
		return nil, err
	}

	headerParentHash := common.Hash{}
	if err := rlp.DecodeBytes(encodedHeader[1], &headerParentHash); err != nil {
		return nil, err
	}

	headerUncleHash := common.Hash{}
	if err := rlp.DecodeBytes(encodedHeader[2], &headerUncleHash); err != nil {
		return nil, err
	}

	headerCoinbase := common.Address{}
	if err := rlp.DecodeBytes(encodedHeader[3], &headerCoinbase); err != nil {
		return nil, err
	}

	headerRoot := common.Hash{}
	if err := rlp.DecodeBytes(encodedHeader[4], &headerRoot); err != nil {
		return nil, err
	}

	headerTxHash := common.Hash{}
	if err := rlp.DecodeBytes(encodedHeader[5], &headerTxHash); err != nil {
		return nil, err
	}

	headerReceiptHash := common.Hash{}
	if err := rlp.DecodeBytes(encodedHeader[6], &headerReceiptHash); err != nil {
		return nil, err
	}

	headerDifficulty := big.NewInt(0)
	if err := rlp.DecodeBytes(encodedHeader[7], headerDifficulty); err != nil {
		return nil, err
	}

	headerGasLimit := uint64(0)
	if err := rlp.DecodeBytes(encodedHeader[8], &headerGasLimit); err != nil {
		return nil, err
	}

	headerGasUsed := uint64(0)
	if err := rlp.DecodeBytes(encodedHeader[9], &headerGasUsed); err != nil {
		return nil, err
	}

	headerTime := uint64(0)
	if err := rlp.DecodeBytes(encodedHeader[10], headerTime); err != nil {
		return nil, err
	}

	headerExtra := []byte{}
	if err := rlp.DecodeBytes(encodedHeader[11], &headerExtra); err != nil {
		return nil, err
	}

	headerMixDigest := common.Hash{}
	if err := rlp.DecodeBytes(encodedHeader[12], &headerMixDigest); err != nil {
		return nil, err
	}

	headerNonce := types.BlockNonce{}
	if err := rlp.DecodeBytes(encodedHeader[13], &headerNonce); err != nil {
		return nil, err
	}

	header := &types.Header{
		Number:      headerNumber,
		ParentHash:  headerParentHash,
		UncleHash:   headerUncleHash,
		Coinbase:    headerCoinbase,
		Root:        headerRoot,
		TxHash:      headerTxHash,
		ReceiptHash: headerReceiptHash,
		Difficulty:  headerDifficulty,
		GasLimit:    headerGasLimit,
		GasUsed:     headerGasUsed,
		Time:        headerTime,
		Extra:       headerExtra,
		MixDigest:   headerMixDigest,
		Nonce:       headerNonce,
	}

	return header, nil
}

// AddBlock
func (s *PrivateAdminAPI) AddBlock(ctx context.Context, tstamp int64, encodedTxs []hexutil.Bytes) (bool, error) {
	fmt.Println("Nico:::AddBlock")
	fmt.Println("tstamp: ", tstamp)
	fmt.Println("encodedTxs: ", encodedTxs)
	// fmt.Println("encodedHeader: ", encodedHeader)

	// encodedHeader hexutil.Bytes
	// use the decodeHeaderFromRequest function to decode header argument
	// header, err := decodeHeaderFromRequest(encodedHeader)
	// if err != nil {
	// 	return false, err
	// }
	// print decoded header
	// fmt.Println("Decoded Header: ", header)

	txs := make([]*types.Transaction, len(encodedTxs))
	results := make(map[common.Hash]map[string]interface{})
	for i, encodedTx := range encodedTxs {
		tx := new(types.Transaction)
		// bytes can't be decoded as transaction - this really shouldn't
		// happen, there is a bug somewhere and we don't want to be silent
		if err := rlp.DecodeBytes(encodedTx, tx); err != nil {
			return false, err
		}
		txs[i] = tx
		results[tx.Hash()] = map[string]interface{}{"txIndex": i}
	}

	fmt.Println("Decoded Txs: ", results)
	fmt.Println("Nico:::AddBlock::CreateBlockFromTxs")
	CreateBlockFromTxs(ctx, s.eth, txs)

	// types.NewBlockWithHeader(result.Header).WithBody(result.Transactions, result.Uncles)

	return true, nil
}

// CreateBlockFromTxs is a helper function that creates a new block with the given transactions and other params.
func CreateBlockFromTxs(ctx context.Context, eth *Ethereum, txs []*types.Transaction) (common.Hash, error) { //  header *types.Header
	/*
		&types.Header{
				Number:      big.NewInt(1),
				ParentHash:  common.HexToHash("0x27c7b2d6df69bc6c016eae2c4a7983aa6819eb9ab5748019bdbc7c2cbbbf356f"),
				UncleHash:   common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
				Coinbase:    common.HexToAddress("0xc0ea08a2d404d3172d2add29a45be56da40e2949"),
				Root:        common.HexToHash("0x77d14e10470b5850332524f8cd6f69ad21f070ce92dca33ab2858300242ef2f1"),
				TxHash:      common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
				ReceiptHash: common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
				Difficulty:  big.NewInt(1),
				GasLimit:    4015682,
				GasUsed:     0,
				Time:        1488928920,
				Extra:       []byte("www.bw.com"),
				MixDigest:   common.HexToHash("0x3e140b0784516af5e5ec6730f2fb20cca22f32be399b9e4ad77d32541f798cd0"),
				Nonce:       types.EncodeNonce(0x0000000000000000), //0x31cbccc8efea6b03f4f8e3376e1f5ffd7771e1d5
			}
	*/

	block := types.NewBlockWithHeader(&types.Header{
		Number:      big.NewInt(1),
		ParentHash:  common.HexToHash("0xfb8964c1a258e5abbd932b1f2ff4b5d763ba79fb000ff1ac1e35632a8bfaaf5e"),
		UncleHash:   common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
		Coinbase:    common.HexToAddress("0x000000000000000000000000000000000000bbbb"),
		Root:        common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
		TxHash:      common.HexToHash("0x65a18e07e16ece3375e6411a64673626ce27f0dcf8526c0a54f176f3c5aadd88"),
		ReceiptHash: common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
		Difficulty:  big.NewInt(131072),
		GasLimit:    9007199254740991,
		GasUsed:     0,
		Time:        1661045890,
		Extra:       []byte("0xf90148a00000000000000000000000000000000000000000000000000000000000000000f8549408b9c73fcc79314c0674534a08f2c8b19b75d4819431cbccc8efea6b03f4f8e3376e1f5ffd7771e1d59498f713957a288099dbbeb195ca80fb8e56a649cd949b85760139f5393d3444a2cfb9de499260d93c28808400000001f8c9b841f009723153e3bc03e2259ef584d3bd185a5262c64674fb98bc5d7d953dc738573f237fefec4d0c88a6a857ce5ea0bc81e2cc293a03bfabbac46e0412fae52c6301b841dd845072f9a078a6a46d1c0803230106383612bbc433d4cb8e49f77444dd92b21358c5d9ca984a8581c26c48b7261c1a22c8625fe271646ad34aee0cac18b2b601b841c997dc86e873c08455733cc66e99cde5ebc192161e9abdc3c8277d3b15446be70112f8dd17f02440f8cd6a1b00e11edee8d67f3d26740097c3d01bda49093de000"),
		MixDigest:   common.HexToHash("0x63746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365"),
		Nonce:       types.EncodeNonce(0x0000000000000000),
	}).WithBody(txs, nil)
	// block := types.NewBlockWithHeader(header).WithBody(txs, nil)

	// print the block
	fmt.Println("Block: ", block)

	// add block to blockchain
	eth.lock.Lock()
	defer eth.lock.Unlock()
	if _, err := eth.blockchain.InsertChain([]*types.Block{block}); err != nil {
		panic(err) // This cannot happen unless the simulator is wrong, fail in that case
	}

	// alt 2
	// w.chain.WriteBlockWithState(b.ChainDb(), block, txs, nil)

	// alternative way to write a block
	// rawdb.WriteBody(db, hash, n, block.Body())
	// rawdb.WriteReceipts(db, hash, n, nil)

	return common.HexToHash("0x3e140b0784516af5e5ec6730f2fb20cca22f32be399b9e4ad77d32541f798cd0"), nil
}

// ExportChain exports the current blockchain into a local file,
// or a range of blocks if first and last are non-nil
func (api *PrivateAdminAPI) ExportChain(file string, first *uint64, last *uint64) (bool, error) {
	if first == nil && last != nil {
		return false, errors.New("last cannot be specified without first")
	}
	if first != nil && last == nil {
		head := api.eth.BlockChain().CurrentHeader().Number.Uint64()
		last = &head
	}
	if _, err := os.Stat(file); err == nil {
		// File already exists. Allowing overwrite could be a DoS vecotor,
		// since the 'file' may point to arbitrary paths on the drive
		return false, errors.New("location would overwrite an existing file")
	}
	// Make sure we can create the file to export into
	out, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return false, err
	}
	defer out.Close()

	var writer io.Writer = out
	if strings.HasSuffix(file, ".gz") {
		writer = gzip.NewWriter(writer)
		defer writer.(*gzip.Writer).Close()
	}

	// Export the blockchain
	if first != nil {
		if err := api.eth.BlockChain().ExportN(writer, *first, *last); err != nil {
			return false, err
		}
	} else if err := api.eth.BlockChain().Export(writer); err != nil {
		return false, err
	}
	return true, nil
}

func hasAllBlocks(chain *core.BlockChain, bs []*types.Block) bool {
	for _, b := range bs {
		if !chain.HasBlock(b.Hash(), b.NumberU64()) {
			return false
		}
	}

	return true
}

// ImportChain imports a blockchain from a local file.
func (api *PrivateAdminAPI) ImportChain(file string) (bool, error) {
	// Make sure the can access the file to import
	in, err := os.Open(file)
	if err != nil {
		return false, err
	}
	defer in.Close()

	var reader io.Reader = in
	if strings.HasSuffix(file, ".gz") {
		if reader, err = gzip.NewReader(reader); err != nil {
			return false, err
		}
	}

	// Run actual the import in pre-configured batches
	stream := rlp.NewStream(reader, 0)

	blocks, index := make([]*types.Block, 0, 2500), 0
	for batch := 0; ; batch++ {
		// Load a batch of blocks from the input file
		for len(blocks) < cap(blocks) {
			block := new(types.Block)
			if err := stream.Decode(block); err == io.EOF {
				break
			} else if err != nil {
				return false, fmt.Errorf("block %d: failed to parse: %v", index, err)
			}
			blocks = append(blocks, block)
			index++
		}
		if len(blocks) == 0 {
			break
		}

		if hasAllBlocks(api.eth.BlockChain(), blocks) {
			blocks = blocks[:0]
			continue
		}
		// Import the batch and reset the buffer
		if _, err := api.eth.BlockChain().InsertChain(blocks); err != nil {
			return false, fmt.Errorf("batch %d: failed to insert: %v", batch, err)
		}
		blocks = blocks[:0]
	}
	return true, nil
}

// PublicDebugAPI is the collection of Ethereum full node APIs exposed
// over the public debugging endpoint.
type PublicDebugAPI struct {
	eth *Ethereum
}

// NewPublicDebugAPI creates a new API definition for the full node-
// related public debug methods of the Ethereum service.
func NewPublicDebugAPI(eth *Ethereum) *PublicDebugAPI {
	return &PublicDebugAPI{eth: eth}
}

// DumpBlock retrieves the entire state of the database at a given block.
func (api *PublicDebugAPI) DumpBlock(blockNr rpc.BlockNumber) (state.Dump, error) {
	if blockNr == rpc.PendingBlockNumber {
		// If we're dumping the pending state, we need to request
		// both the pending block as well as the pending state from
		// the miner and operate on those
		_, stateDb := api.eth.miner.Pending()
		return stateDb.RawDump(false, false, true), nil
	}
	var block *types.Block
	if blockNr == rpc.LatestBlockNumber {
		block = api.eth.blockchain.CurrentBlock()
	} else {
		block = api.eth.blockchain.GetBlockByNumber(uint64(blockNr))
	}
	if block == nil {
		return state.Dump{}, fmt.Errorf("block #%d not found", blockNr)
	}
	stateDb, err := api.eth.BlockChain().StateAt(block.Root())
	if err != nil {
		return state.Dump{}, err
	}
	return stateDb.RawDump(false, false, true), nil
}

// PrivateDebugAPI is the collection of Ethereum full node APIs exposed over
// the private debugging endpoint.
type PrivateDebugAPI struct {
	eth *Ethereum
}

// NewPrivateDebugAPI creates a new API definition for the full node-related
// private debug methods of the Ethereum service.
func NewPrivateDebugAPI(eth *Ethereum) *PrivateDebugAPI {
	return &PrivateDebugAPI{eth: eth}
}

// Preimage is a debug API function that returns the preimage for a sha3 hash, if known.
func (api *PrivateDebugAPI) Preimage(ctx context.Context, hash common.Hash) (hexutil.Bytes, error) {
	if preimage := rawdb.ReadPreimage(api.eth.ChainDb(), hash); preimage != nil {
		return preimage, nil
	}
	return nil, errors.New("unknown preimage")
}

// BadBlockArgs represents the entries in the list returned when bad blocks are queried.
type BadBlockArgs struct {
	Hash  common.Hash            `json:"hash"`
	Block map[string]interface{} `json:"block"`
	RLP   string                 `json:"rlp"`
}

// GetBadBlocks returns a list of the last 'bad blocks' that the client has seen on the network
// and returns them as a JSON list of block-hashes
func (api *PrivateDebugAPI) GetBadBlocks(ctx context.Context) ([]*BadBlockArgs, error) {
	blocks := api.eth.BlockChain().BadBlocks()
	results := make([]*BadBlockArgs, len(blocks))

	var err error
	for i, block := range blocks {
		results[i] = &BadBlockArgs{
			Hash: block.Hash(),
		}
		if rlpBytes, err := rlp.EncodeToBytes(block); err != nil {
			results[i].RLP = err.Error() // Hacky, but hey, it works
		} else {
			results[i].RLP = fmt.Sprintf("0x%x", rlpBytes)
		}
		if results[i].Block, err = ethapi.RPCMarshalBlock(block, true, true); err != nil {
			results[i].Block = map[string]interface{}{"error": err.Error()}
		}
	}
	return results, nil
}

// AccountRangeResult returns a mapping from the hash of an account addresses
// to its preimage. It will return the JSON null if no preimage is found.
// Since a query can return a limited amount of results, a "next" field is
// also present for paging.
type AccountRangeResult struct {
	Accounts map[common.Hash]*common.Address `json:"accounts"`
	Next     common.Hash                     `json:"next"`
}

func accountRange(st state.Trie, start *common.Hash, maxResults int) (AccountRangeResult, error) {
	if start == nil {
		start = &common.Hash{0}
	}
	it := trie.NewIterator(st.NodeIterator(start.Bytes()))
	result := AccountRangeResult{Accounts: make(map[common.Hash]*common.Address), Next: common.Hash{}}

	if maxResults > AccountRangeMaxResults {
		maxResults = AccountRangeMaxResults
	}

	for i := 0; i < maxResults && it.Next(); i++ {
		if preimage := st.GetKey(it.Key); preimage != nil {
			addr := &common.Address{}
			addr.SetBytes(preimage)
			result.Accounts[common.BytesToHash(it.Key)] = addr
		} else {
			result.Accounts[common.BytesToHash(it.Key)] = nil
		}
	}

	if it.Next() {
		result.Next = common.BytesToHash(it.Key)
	}

	return result, nil
}

// AccountRangeMaxResults is the maximum number of results to be returned per call
const AccountRangeMaxResults = 256

// AccountRange enumerates all accounts in the latest state
func (api *PrivateDebugAPI) AccountRange(ctx context.Context, start *common.Hash, maxResults int) (AccountRangeResult, error) {
	var statedb *state.StateDB
	var err error
	block := api.eth.blockchain.CurrentBlock()

	if len(block.Transactions()) == 0 {
		statedb, err = api.computeStateDB(block, defaultTraceReexec)
		if err != nil {
			return AccountRangeResult{}, err
		}
	} else {
		_, _, statedb, err = api.computeTxEnv(block.Hash(), len(block.Transactions())-1, 0)
		if err != nil {
			return AccountRangeResult{}, err
		}
	}

	trie, err := statedb.Database().OpenTrie(block.Header().Root)
	if err != nil {
		return AccountRangeResult{}, err
	}

	return accountRange(trie, start, maxResults)
}

// StorageRangeResult is the result of a debug_storageRangeAt API call.
type StorageRangeResult struct {
	Storage storageMap   `json:"storage"`
	NextKey *common.Hash `json:"nextKey"` // nil if Storage includes the last key in the trie.
}

type storageMap map[common.Hash]storageEntry

type storageEntry struct {
	Key   *common.Hash `json:"key"`
	Value common.Hash  `json:"value"`
}

// StorageRangeAt returns the storage at the given block height and transaction index.
func (api *PrivateDebugAPI) StorageRangeAt(ctx context.Context, blockHash common.Hash, txIndex int, contractAddress common.Address, keyStart hexutil.Bytes, maxResult int) (StorageRangeResult, error) {
	_, _, statedb, err := api.computeTxEnv(blockHash, txIndex, 0)
	if err != nil {
		return StorageRangeResult{}, err
	}
	st := statedb.StorageTrie(contractAddress)
	if st == nil {
		return StorageRangeResult{}, fmt.Errorf("account %x doesn't exist", contractAddress)
	}
	return storageRangeAt(st, keyStart, maxResult)
}

func storageRangeAt(st state.Trie, start []byte, maxResult int) (StorageRangeResult, error) {
	it := trie.NewIterator(st.NodeIterator(start))
	result := StorageRangeResult{Storage: storageMap{}}
	for i := 0; i < maxResult && it.Next(); i++ {
		_, content, _, err := rlp.Split(it.Value)
		if err != nil {
			return StorageRangeResult{}, err
		}
		e := storageEntry{Value: common.BytesToHash(content)}
		if preimage := st.GetKey(it.Key); preimage != nil {
			preimage := common.BytesToHash(preimage)
			e.Key = &preimage
		}
		result.Storage[common.BytesToHash(it.Key)] = e
	}
	// Add the 'next key' so clients can continue downloading.
	if it.Next() {
		next := common.BytesToHash(it.Key)
		result.NextKey = &next
	}
	return result, nil
}

// GetModifiedAccountsByNumber returns all accounts that have changed between the
// two blocks specified. A change is defined as a difference in nonce, balance,
// code hash, or storage hash.
//
// With one parameter, returns the list of accounts modified in the specified block.
func (api *PrivateDebugAPI) GetModifiedAccountsByNumber(startNum uint64, endNum *uint64) ([]common.Address, error) {
	var startBlock, endBlock *types.Block

	startBlock = api.eth.blockchain.GetBlockByNumber(startNum)
	if startBlock == nil {
		return nil, fmt.Errorf("start block %x not found", startNum)
	}

	if endNum == nil {
		endBlock = startBlock
		startBlock = api.eth.blockchain.GetBlockByHash(startBlock.ParentHash())
		if startBlock == nil {
			return nil, fmt.Errorf("block %x has no parent", endBlock.Number())
		}
	} else {
		endBlock = api.eth.blockchain.GetBlockByNumber(*endNum)
		if endBlock == nil {
			return nil, fmt.Errorf("end block %d not found", *endNum)
		}
	}
	return api.getModifiedAccounts(startBlock, endBlock)
}

// GetModifiedAccountsByHash returns all accounts that have changed between the
// two blocks specified. A change is defined as a difference in nonce, balance,
// code hash, or storage hash.
//
// With one parameter, returns the list of accounts modified in the specified block.
func (api *PrivateDebugAPI) GetModifiedAccountsByHash(startHash common.Hash, endHash *common.Hash) ([]common.Address, error) {
	var startBlock, endBlock *types.Block
	startBlock = api.eth.blockchain.GetBlockByHash(startHash)
	if startBlock == nil {
		return nil, fmt.Errorf("start block %x not found", startHash)
	}

	if endHash == nil {
		endBlock = startBlock
		startBlock = api.eth.blockchain.GetBlockByHash(startBlock.ParentHash())
		if startBlock == nil {
			return nil, fmt.Errorf("block %x has no parent", endBlock.Number())
		}
	} else {
		endBlock = api.eth.blockchain.GetBlockByHash(*endHash)
		if endBlock == nil {
			return nil, fmt.Errorf("end block %x not found", *endHash)
		}
	}
	return api.getModifiedAccounts(startBlock, endBlock)
}

func (api *PrivateDebugAPI) getModifiedAccounts(startBlock, endBlock *types.Block) ([]common.Address, error) {
	if startBlock.Number().Uint64() >= endBlock.Number().Uint64() {
		return nil, fmt.Errorf("start block height (%d) must be less than end block height (%d)", startBlock.Number().Uint64(), endBlock.Number().Uint64())
	}
	triedb := api.eth.BlockChain().StateCache().TrieDB()

	oldTrie, err := trie.NewSecure(startBlock.Root(), triedb)
	if err != nil {
		return nil, err
	}
	newTrie, err := trie.NewSecure(endBlock.Root(), triedb)
	if err != nil {
		return nil, err
	}
	diff, _ := trie.NewDifferenceIterator(oldTrie.NodeIterator([]byte{}), newTrie.NodeIterator([]byte{}))
	iter := trie.NewIterator(diff)

	var dirty []common.Address
	for iter.Next() {
		key := newTrie.GetKey(iter.Key)
		if key == nil {
			return nil, fmt.Errorf("no preimage found for hash %x", iter.Key)
		}
		dirty = append(dirty, common.BytesToAddress(key))
	}
	return dirty, nil
}
