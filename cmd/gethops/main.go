package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	/* flag */
	genesisFile = flag.String("genesis", os.Getenv("GETH_X_GENESIS"), "Genesis file path -> Info. (ex: get coinbase address to set --miner.etherbase)")
	nodekeyFile = flag.String("nodekey", os.Getenv("GETH_X_NODEKEY"), "Nodekey file -> Public key. (ex: use it to config static nodes)")
	infoCmd     = flag.String("get", "", "Single info to get from genesis [alloc, chainid, coinbase, gaslimit] or nodekey [address, publickey]")
)

func main() {
	flag.Parse()

	if len(*genesisFile) == 0 && len(*nodekeyFile) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	if len(*genesisFile) > 0 && len(*nodekeyFile) > 0 {
		log.Fatalf("use [%s] or [%s] one at a time", "genesis", "nodekey")
	}

	request := strings.ToLower(*infoCmd)

	/* genesis */
	if len(*genesisFile) > 0 {
		if genesis, err := genesisFrom(*genesisFile); err != nil {
			log.Fatalf("genesis - file [%s] - %v", *genesisFile, err)
		} else {
			switch request {
			case "alloc":
				alloc, _ := json.Marshal(genesis.Alloc)
				fmt.Printf("%s ", alloc)
			case "chainid":
				fmt.Printf("%s", genesis.Config.ChainID)
			case "coinbase":
				fmt.Printf("%s", genesis.Coinbase)
			case "gaslimit":
				fmt.Printf("%d", genesis.GasLimit)
			default:
				log.Printf("genesis requests available: [%s, %s, %s, %s]\n", "alloc", "chainid", "coinbase", "gaslimit")
				log.Fatalf("unknown genesis request: [%s] ", request)
			}
		}
		return
	}

	/* nodekey */
	if len(*nodekeyFile) > 0 {
		switch request {
		case "address":
			if nodekeyAddress, err := nodekeyAddressFrom(*nodekeyFile); err != nil {
				log.Fatalf("nodekey - file [%s] - %v", *nodekeyFile, err)
			} else {
				fmt.Printf("%s", nodekeyAddress)
			}
		case "publickey":
			if nodekeyPub, err := nodekeyPublicFrom(*nodekeyFile); err != nil {
				log.Fatalf("nodekey - file [%s] - %v", *nodekeyFile, err)
			} else {
				fmt.Printf("%s", nodekeyPub)
			}
		default:
			log.Printf("nodekey requests available: [%s, %s]\n", "address", "publickey")
			log.Fatalf("unknown nodekey request: [%s] ", request)
		}
		return
	}

}

func genesisFrom(file string) (core.Genesis, error) {
	var genesis core.Genesis

	genesisBlob, err := ioutil.ReadFile(file)
	if err != nil {
		return genesis, err
	}

	err = json.Unmarshal(genesisBlob, &genesis)

	return genesis, err
}

func nodekeyPublicFrom(file string) (string, error) {
	var nodekeyPub string

	nodekeyBlob, err := ioutil.ReadFile(file)
	if err != nil {
		return nodekeyPub, err
	}

	/* private key */
	privateKey, err := crypto.HexToECDSA(string(nodekeyBlob))
	if err != nil {
		return nodekeyPub, err
	}

	/* public key */
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nodekeyPub, fmt.Errorf("publicKey.(*ecdsa.PublicKey) failed")
	}
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	nodekeyPub = hexutil.Encode(publicKeyBytes)[4:] // [4:] 0x04 stripped

	return nodekeyPub, nil
}

func nodekeyAddressFrom(file string) (string, error) {
	var address string

	nodekeyBlob, err := ioutil.ReadFile(file)
	if err != nil {
		return address, err
	}
	/* private key */
	privateKey, err := crypto.HexToECDSA(string(nodekeyBlob))
	if err != nil {
		return address, err
	}

	/* public key */
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return address, fmt.Errorf("publicKey.(*ecdsa.PublicKey) failed")
	}

	/* address */
	address = crypto.PubkeyToAddress(*publicKeyECDSA).Hex() // EIP55-compliant

	return address, nil
}
