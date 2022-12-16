#!/usr/bin/env bash

# In order to run this script, you need to:
#
# 1. create ./tmp/geth_data directories
#
# 2. copy the content of 
# milkomeda-rollup/deployments/a1-devenet/quorum/storage
# to ./tmp/geth_data/
#
# 3. make geth gethops
#
# 4. run this script and tada!
###############################################################

set -euxo pipefail

NETWORK_ID=${NETWORK_ID:-200202}
MINER_GASPRICE=${MINER_GASPRICE:-20000000000}
NODE_IDENTITY="thegraph-node"

MINER_ETHERBASE="0x0000000000000000000000000000000000000000"
MINER_GASLIMIT=30000000 # will be changed by genesis gasLimit

DATA_PATH="./tmp_devnet/geth_data" # "/tmp/milkomeda-a1-devnet/storage/quorum"

GENESIS_FILE="${DATA_PATH}/genesis.json" # provided by observer
GENESIS_BACKUP_FILE="${DATA_PATH}/genesis_last.json"

NODEKEY_FILE="${DATA_PATH}/geth/nodekey" # generated from geth init

genesis_coinbase() {
    # genesis file expected to be provided by observer
    if [ ! -f ${GENESIS_FILE} ]; then exit 1; fi
    MINER_ETHERBASE=$(./build/bin/gethops -genesis=${GENESIS_FILE} -get=coinbase) || exit 1
}

genesis_gaslimit() {
    # genesis file expected to be provided by observer
    if [ ! -f ${GENESIS_FILE} ]; then exit 1; fi
    MINER_GASLIMIT=$(./build/bin/gethops -genesis=${GENESIS_FILE} -get=gaslimit) || exit 1
}

public_nodekey() {
    if [ ! -f ${NODEKEY_FILE} ]; then exit 1; fi
    NODEKEY_PUBLIC=$(./build/bin/gethops -nodekey=${NODEKEY_FILE} -get=publickey) || exit 1
    # static-nodes init
    if [ ! -f "${DATA_PATH}/static-nodes.json" ]; then
        echo "[\"enode://${NODEKEY_PUBLIC}@127.0.0.1:30303?discport=0&raftport=53000\"]" > "${DATA_PATH}/static-nodes.json"
    fi
}

init_chain() {
    # genesis file expected to be provided from observer
    if [ ! -f ${GENESIS_FILE} ]; then exit 1; fi

    # genesis init
    if [ ! -d "${DATA_PATH}/geth/chaindata" ]; then
        if [ ! -f ${GENESIS_FILE} ]; then exit 1; fi
        ./build/bin/geth --nodiscover --datadir "${DATA_PATH}" init "${GENESIS_FILE}"
        cp "${GENESIS_FILE}" "${GENESIS_BACKUP_FILE}"
    fi

    # genesis file updated - init again
    if [ -f "${GENESIS_BACKUP_FILE}" ] && [ -f "${GENESIS_FILE}" ] && ! cmp -s "${GENESIS_FILE}" "${GENESIS_BACKUP_FILE}"; then
        echo "Genesis has changed. This will reset the chain, but needs to be handled manualy on production"
        exit 1
#        geth --nodiscover --datadir "${DATA_PATH}" init "${GENESIS_FILE}"
#        cp "${GENESIS_FILE}" "${GENESIS_BACKUP_FILE}"
    fi
}

prune_prev_state() {
    cd tmp_devnet/geth_data
    mv genesis.json ./..
    rm -rf *
    mv ../genesis.json .
    cd ../..
}

start_node() {
    ./build/bin/geth \
        --networkid 200202 \
        --datadir "${DATA_PATH:-/tmp/geth_data}" \
        --dev \
        --syncmode full \
        --gcmode archive \
        --fakepow \
        --verbosity 5 \
        --nodiscover \
        --debug \
        --rpc \
        --rpcapi="eth,web3,personal,net,admin" \
        --ws \
        --port 30303 \
        --pprof \
        --nat none \
        --identity "${NODE_IDENTITY:-node$$}"
}

start() {
    prune_prev_state
    genesis_coinbase
    genesis_gaslimit
    init_chain
    # public_nodekey
    start_node
}

start
