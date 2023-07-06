# Axiom V1 Core Contracts

## Setup

Clone this repository (and git submodule dependencies) with

```bash
git clone --recurse-submodules -j8 https://github.com/axiom-crypto/axiom-v1-contracts.git
cd axiom-v1-contracts
```

### RPC URL

```bash
cp .env.example .env
```

Fill in `.env` with your `MAINNET_RPC_URL` and/or `GOERLI_RPC_URL`.

## Contracts: High-level overview

The three main contracts in this repository are `AxiomV1`, `AxiomV1StoragePf`, and `AxiomV1Query`. They are all designed to be deployed using OpenZeppelin UUPS [proxies](https://docs.openzeppelin.com/contracts/4.x/api/proxy) and the contracts themselves are [UUPS Upgradeable](https://docs.openzeppelin.com/contracts/4.x/api/proxy#UUPSUpgradeable). The UUPS proxy is [`AxiomProxy`](contracts/AxiomProxy.sol).

### `AxiomV1`

`AxiomV1` inherits `AxiomV1Core` and implements UUPS Upgradeability. All upgrades, including upgrades of the underlying SNARK verifier addresses, are controlled by a OpenZeppelin [`TimelockController`](https://docs.openzeppelin.com/contracts/4.x/api/governance#TimelockController), which on deployment will be controlled by an Axiom multisig. To rule out the possibility of timelock bypass by metamorphic contracts, users should verify that the contracts deployed at verifier contracts do not contain the `SELFDESTRUCT` or `DELEGATECALL` opcodes. This can be done by viewing all contract opcodes on Etherscan as detailed [here](https://ethereum.org/en/developers/tutorials/reverse-engineering-a-contract/#prepare-the-executable-code).

`AxiomV1Core` is the core Axiom contract for caching all historic Ethereum block hashes. The overall goal is that the contract state [`IAxiomV1State`](contracts/interfaces/core/IAxiomV1State.sol) should contain commitments to all Ethereum block hashes from genesis to `recentBlockNumber` where `recentBlockNumber` is in `[block.number - 256, block.number)`.

These historic block hashes are stored in two ways:

- As a Merkle root corresponding to a batch of block numbers `[startBlockNumber, startBlockNumber + numFinal)` where `startBlockNumber` is a multiple of `1024`, and `numFinal` is in `[1,1024]`. This is stored in `historicalRoots`.
- As a Merkle mountain range of the Merkle roots of batches of 1024 block hashes starting from genesis to a recent block. The block hashes committed to by this Merkle mountain range will always be a subset of those whose Merkle roots are stored in the previous format.

#### Updating the cache of Merkle roots

The cache of Merkle roots of block hashes in `historicalRoots`, and the interface to update it is provided in [`IAxiomV1Update`](contracts/interfaces/core/IAxiomV1Update.sol). The following functions allow for updates:

- `updateRecent`: Verifies a zero-knowledge proof that proves the block header commitment chain from `[startBlockNumber, startBlockNumber + numFinal)` is correct, where `startBlockNumber` is a multiple of `1024`, and `numFinal` is in `[1,1024]`. This reverts unless `startBlockNumber + numFinal - 1` is in `[block.number - 256, block.number)`, i.e., if `blockhash(startBlockNumber + numFinal - 1)` is accessible from within the smart contract at the block this function is called. The zero-knowledge proof checks that each parent hash is in the block header of the next block, and that the block header RLP hashes to the block hash. This is accepted only if the block hash of `startBlockNumber + numFinal - 1`, according to the zero-knowledge proof, matches the block hash according to the EVM.
- `updateOld`: Verifies a zero-knowledge proof that proves the block header commitment chain from `[startBlockNumber, startBlockNumber + 1024)` is correct, where block `startBlockNumber + 1024` must already be cached by the smart contract. This stores a single new Merkle root in the cache.
- `updateHistorical`: Same as `updateOld` except that it uses a different zero-knowledge proof to prove the block header commitment chain from `[startBlockNumber, startBlockNumber + 2 ** 17)`. Requires block `startBlockNumber + 2 ** 17` to already be cached by the smart contract. This stores `2 ** 7 = 128` new Merkle roots in the cache.

As an initial safety feature, the `update*` functions are permissioned to only be callable by a 'prover' role.

#### Updating the Merkle mountain range

We store a Merkle mountain range in `historicalMMR` which commits to a continguous chain of Merkle roots of 1024 consecutive block hashes starting from genesis. We cache commitments to recent values of `historicalMMR` in the ring buffer `mmrRingBuffer` to facilitate asynchronous proving against a Merkle mountain range which may be updated on-chain during proving. To update `historicalMMR`, we use newly verified Merkle roots added to `historicalRoots`. We provide two update methods:

- `updateRecent`: If the chain of 1024 blocks represented by a newly added Merkle root is contiguous with the last blocks committed to by `historicalMMR`, we extend it by a single new Merkle root and update the cache in `mmrRingBuffer`.
- `appendHistoricalMMR`: If there are new Merkle roots in `historicalRoots` which are not committed to in `historicalMMR` (usually because they were added by `updateOld`), this function appends them to `historicalMMR` in a single batch.

#### Reading from the cache

We envision most users will primarily interact with the [`IAxiomV1Verifier`](contracts/interfaces/core/IAxiomV1Verifier.sol) interface to read from the block hash cache.

To verify the block hash of a block within the last `256` most recent blocks, we provide a helper function `isRecentBlockHashValid`.

To verify a historical block hash, one should use the `isBlockHashValid` method which takes in a witness that a block hash is included in the cache, formatted via struct `IAxiomV1Verifier.BlockHashWitness`. This provides a Merkle proof of a block hash into the Merkle root of a batch (up to `1024` blocks) stored in `historicalRoots`. The `isBlockHashValid` method verifies that the Merkle proof is a valid Merkle path for the relevant block hash and checks that the Merkle root lies in the cache.

Lastly, one can verify a block hash by verifying a Merkle proof into the cached Merkle mountain range. This is done using the function `mmrVerifyBlockHash`. Since Merkle mountain ranges are stored in a ring buffer, the user must specify the index of the MMR in the ring buffer.

### `AxiomV1StoragePf`

`AxiomV1StoragePf` implements UUPS Upgradeability. All upgrades, including upgrades of the underlying SNARK verifier addresses, are controlled by a OpenZeppelin [`TimelockController`](https://docs.openzeppelin.com/contracts/4.x/api/governance#TimelockController), which on deployment will be controlled by an Axiom multisig. To rule out the possibility of timelock bypass by metamorphic contracts, users should verify that the contracts deployed at verifier contracts do not contain the `SELFDESTRUCT` or `DELEGATECALL` opcodes. This can be done by viewing all contract opcodes on Etherscan as detailed [here](https://ethereum.org/en/developers/tutorials/reverse-engineering-a-contract/#prepare-the-executable-code).

The `AxiomV1StoragePf` contract uses `AxiomV1` to attest to the values of storage slots in any account in any Ethereum block.

This is done with the `attestSlots` function, which accepts a zero-knowledge proof that proves the values of `10` storage slots of a single account in a single block, given a trusted block hash for that block. The zero-knowledge proof proves Merkle-Patricia Trie inclusion into the storage root of that account, and of the account into the state root of that block. The smart contract uses `AxiomV1` to validate that the block hash of the block in question is correct.

As an initial safety feature, the `attestSlots` function is permissioned to only be callable by a 'prover' role.

Once slot values have been attested to, they are stored in contract storage. Users can then verify these slot values by calling `isSlotAttestationValid`.

### `AxiomV1Query`

`AxiomV1Query` implements UUPS Upgradeability. All upgrades, including upgrades of the underlying SNARK verifier addresses, are controlled by a OpenZeppelin [`TimelockController`](https://docs.openzeppelin.com/contracts/4.x/api/governance#TimelockController), which is controlled by Axiom.

The `AxiomV1Query` contract uses `AxiomV1` to attest to the Merkle-ized values of arbitrary block headers, account fields, and storage slots from any number of Ethereum blocks. It supports:

- On-chain query requests with on- or off-chain data availability for queries and on-chain payment or refunds.
- On-chain fulfillment of queries with on-chain proof verification.

We specify queries by the hash `keccakQueryResponse = keccak256(keccakBlockResponse, keccakAccountResponse, keccakStorageResponse)`, where:

- `keccakBlockResponse` is the Keccak Merkle root of a depth `QUERY_MERKLE_DEPTH` tree whose leaves are given by `keccak(blockHash . blockNumber)`
- `keccakAccountResponse` is the Keccak Merkle root of a depth `QUERY_MERKLE_DEPTH` tree whose leaves are given by `keccak(blockNumber . addr . keccak(nonce . balance . storageRoot . codeHash))`, where `nonce` is 0-padded to 8 bytes and `balance` is 0-padded to 12 bytes.
- `keccakStorageReponse` is the Keccak Merkle root of a depth `QUERY_MERKLE_DEPTH` tree whose leaves are given by `keccak(blockNumber . addr . slot . value)`.

On-chain query requests are stored in `queries`, which is a mapping between `keccakQueryResponse` and `AxiomQueryMetadata`. The relevant data of a query is:

- `payment` -- The number of wei offered for fulfillment.
- `state` -- Either `Inactive` (not initiated or refunded), `Active` (in progress), or `Fulfilled` (already proven on-chain).
- `deadlineBlockNumber` -- The block after which a refund is possible.
- `refundee` -- The address to send a refund to.

We store verified results in `verifiedKeccakResults` and `verifiedPoseidonResults`, which record:

- Whether a query corresponding to `keccakQueryResponse` has been proven on-chain.
- Whether a query corresponding to `poseidonQueryResponse` has been proving on-chain. In this case, `poseidonQueryResponse` has a more complicated format:
  - `poseidonQueryResponse = keccak(poseidonBlockResponse, poseidonAccountResponse, poseidonStorageResponse)`
  - `poseidonBlockResponse` is the Poseidon Merkle root of a depth `QUERY_MERKLE_DEPTH` tree whose leaves are given by:
    - `poseidon(blockHash . blockNumber . poseidon_tree_root(blockHeaderFields))`.
  - `poseidonAccountResponse` is the Poseidon Merkle root of a depth `QUERY_MERKLE_DEPTH` tree whose leaves are given by:
    - `poseidon(poseidon(blockHash . blockNumber . poseidon_tree_root(blockHeaderFields)) . poseidon(stateRoot . address . poseidon_tree_root(accountFields)))`.
  - `poseidonStorageResponse` is the Poseidon Merkle root of a depth `QUERY_MERKLE_DEPTH` tree whose leaves are given by:
    - `poseidon(poseidon(blockHash . blockNumber . poseidon_tree_root(blockHeaderFields)) . poseidon(stateRoot . address . poseidon_tree_root(accountFields)) . poseidon(storageRoot . slot . value)`.

#### Initiating queries on-chain

Users can interact with queries on-chain as follows:

- Anyone can initiate a query with either on- or off-chain data availability:
  - `sendQuery` -- Request a proof for `keccakQueryResponse`. This allows the caller to specify a `refundee` and also provide on-chain data availability for the query in `query`, whose contents are not checked.
  - `sendOffchainQuery`-- Request a proof for `keccakQueryResponse`. This allows the caller to specify a `refundee` and also provide on-chain data availability for the query in `ipfsHash`, whose contents are not checked.
- Fulfillment happens by submitting a proof that verifies `keccakQueryResponse` against the cache of block hashes in `AxiomV1`. We have permissioned fulfillment to the `onlyProver` role for safety at the moment.
  - `fulfillQueryVsMMR` allows a prover to supply a proof which proves `keccakQueryResponse` was correct against the Merkle Mountain range stored in index `mmrIdx` of `AxiomV1.mmrRingBuffer`. The prover must also pass some additional witness data in `mmrWitness` and the ZK proof itself in `proof`. The prover can collect payment to `payee`.
  - This works by calling `_verifyResultVsMMR`, detailed below.
- Refunds may be processed if a query has not been fulfilled by its deadline.
  - `collectRefund` allows anyone to process a refund for a query specified by `keccakQueryResponse`.

#### Query verification

Any query result, whether it is made on-chain or not, may be verified via `verifyResultVsMMR`. This is permissioned to the `onlyProver` role for safety at the moment. It works by calling `_verifyResultVsMMR`, which does the following operations:

- Uses the verifier deployed at `mmrVerifierAddress` to verify a SNARK proof that:
  - Has public inputs given by the following. Here, hi-lo form means a uint256 `(a << 128) + b` is represented as two uint256's `a` and `b`, each of which is guaranteed to contain a uint128. `mmr` is a variable length array of bytes32 containing the Merkle Mountain Range that `proof` is proving into, and `mmr[idx]` is either `bytes32(0)` or the Merkle root of `1 << idx` block hashes.
    - `poseidonBlockResponse` as a field element
    - `keccakBlockResponse` as 2 field elements, in hi-lo form
    - `poseidonAccountResponse` as a field element
    - `keccakAccountResponse` as 2 field elements, in hi-lo form
    - `poseidonStorageResponse` as a field element
    - `keccakStorageResponse` as 2 field elements, in hi-lo form
    - `historicalMMRKeccak` which is `keccak256(abi.encodePacked(mmr[10:]))` as 2 field elements in hi-lo form.
    - `recentMMRKeccak` which is `keccak256(abi.encodePacked(mmr[:10]))` as 2 field elements in hi-lo form.
  - Proves `{poseidon, keccak}{Block, Account, Storage}Response` are consistent relative to the Merkle Mountain range of block hashes committed to in `historicalMMRKeccak` and `recentMMRKeccak`.
- Uses the additional witness data in `mmrWitness` to check that `historicalMMRKeccak` and `recentMMRKeccak` are consistent with the on-chain cache of block hashes in `AxiomV1` by checking:
  - `historicalMMRKeccak` appears in index `mmrIndex` of `AxiomV1.mmrRingBuffer`.
  - `recentMMRKeccak` is either committed to by an element of `AxiomV1.historicalRoots` or is an extension of such an element by block hashes accessible to the EVM.
- If all checks pass, store `keccakQueryResponse` and `poseidonQueryResponse` in `verifiedKeccakResults` and `verifiedPoseidonResults`.

#### Reading verified query results

We support reading from verified query results via:

- `isKeccakResultValid` -- Check whether a query consisting of `keccakBlockResponse`, `keccakAccountResponse`, and `keccakStorageResponse` has already been verified.
- `isPoseidonResultValid` -- Check whether a query consisting of `poseidonBlockResponse`, `poseidonAccountResponse`, and `poseidonStorageResponse` has already been verified.
- `areResponsesValid` -- Check whether queries into block, account, and storage data have been verified. Each query is specified by:
  - `BlockResponse` -- The `blockNumber` and `blockHash` as well as a Merkle proof `proof` and leaf location `leafIdx` in `keccakBlockResponse`.
  - `AccountResponse` -- The `blockNumber`, `addr`, `nonce`, `balance`, `storageRoot`, and `codeHash` as well as a Merkle proof `proof` and leaf location `leafIdx` in `keccakAccountResponse`.
  - `StorageResponse` -- The `blockNumber`, `addr`, `slot`, and `value` as well as a Merkle proof `proof` and leaf location `leafIdx` in `keccakStorageResponse`.

## Smart Contract Testing

We use [foundry](https://book.getfoundry.sh/) for smart contract development and testing. You can follow these [instructions](https://book.getfoundry.sh/getting-started/installation) to install it.

Copy `.env.example` to `.env` and fill in accordingly.
In order for Forge to access `MAINNET_RPC_URL` for testing, we need to export `.env`:

```bash
set -a
source .env
set +a
```

After installing `foundry`, run:

```bash
forge install
forge test
```

For verbose logging of events and gas tracking, run

```bash
forge test -vvvv
```

### Local testing with mainnet fork

We can test contract deployment with a local fork of Ethereum mainnet using Foundry [anvil](https://book.getfoundry.sh/reference/anvil/). To start the local anvil node by forking mainnet from a specified block number, run:

```bash
bash script/local/start_anvil.sh
```

in the `contracts` directory. Now that anvil is running, we can deploy the SNARK verifiers, `AxiomV1` upgradeable contract, and the proxy contract together by running

```bash
bash script/local/deploy_core_local.sh
```

This will print out verbose logs of the deployment, including the addresses of **multiple** deployed contracts (SNARK verifier, historical SNARK verifier, `AxiomV1`, and `AxiomProxy`).

To test deployment of `AxiomV1Query`, we can run (independently of `deploy_core_local.sh`)

```bash
bash script/local/deploy_query_local.sh
```

This will print out verbose logs of the deployment, including the addresses of **multiple** deployed contracts (SNARK verifier, historical SNARK verifier, query MMR SNARK verifier, `AxiomV1`, `AxiomV1Query`, and `AxiomProxy`).

### Code Analysis for contributors

To generate documents to better understand and analyze the code we can run

```bash
bash script/local/code_analysis.sh
```

This generates the following files (links below)

1. [axiom-v1-contracts.png](./docs/axiom-v1-contracts.png)
: Useful for undertanding the axiom-v1-contracts their functions and relationships
2. [axiom-v1-contracts-coverage-report](https://htmlpreview.github.io/?./docs/coverage/index.html): Useful for reviewing test coverage for Axiom contracts.
   - *Note: to see the report locally open `./docs/coverage/index.html` in your web browser.*
   - *Note: coverage report needs [lcov](https://github.com/linux-test-project/lcov) installed e.g. for mac use [Homebrew Formulae lcov](https://formulae.brew.sh/formula/lcov)*
3. [axiom-v1-contracts.log](./docs/axiom-v1-contracts.log)
