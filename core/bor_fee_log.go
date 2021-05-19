package core

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/deepmind"
)

var transferLogSig = common.HexToHash("0xe6497e3ee548a3372136af2fcb0696db31fc6cf20260707645068bd3fe97f3c4")
var transferFeeLogSig = common.HexToHash("0x4dfe1bbbcf077ddc3e01291eea2d5c70c2b422b415d95645b9adcfd678cb1d63")
var feeAddress = common.HexToAddress("0x0000000000000000000000000000000000001010")
var bigZero = big.NewInt(0)

// AddTransferLog adds transfer log into state
func AddTransferLog(
	state vm.StateDB,

	sender,
	recipient common.Address,

	amount,
	input1,
	input2,
	output1,
	output2 *big.Int,
	dmContext *deepmind.Context,
) {
	addTransferLog(
		state,
		transferLogSig,

		sender,
		recipient,

		amount,
		input1,
		input2,
		output1,
		output2,
		dmContext,
	)
}

// AddFeeTransferLog adds transfer log into state
func AddFeeTransferLog(
	state vm.StateDB,

	sender,
	recipient common.Address,

	amount,
	input1,
	input2,
	output1,
	output2 *big.Int,
	dmContext *deepmind.Context,
) {
	addTransferLog(
		state,
		transferFeeLogSig,

		sender,
		recipient,

		amount,
		input1,
		input2,
		output1,
		output2,
		dmContext,
	)
}

// addTransferLog adds transfer log into state
func addTransferLog(
	state vm.StateDB,
	eventSig common.Hash,

	sender,
	recipient common.Address,

	amount,
	input1,
	input2,
	output1,
	output2 *big.Int,
	dmContext *deepmind.Context,
) {
	// ignore if amount is 0
	if amount.Cmp(bigZero) <= 0 {
		return
	}

	dataInputs := []*big.Int{
		amount,
		input1,
		input2,
		output1,
		output2,
	}

	var data []byte
	for _, v := range dataInputs {
		data = append(data, common.LeftPadBytes(v.Bytes(), 32)...)
	}

	// add transfer log
	state.AddLog(&types.Log{
		Address: feeAddress,
		Topics: []common.Hash{
			eventSig,
			feeAddress.Hash(),
			sender.Hash(),
			recipient.Hash(),
		},
		Data: data,
	}, dmContext)
}