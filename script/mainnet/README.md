# Mainnet Deployment

## Setup

Install `solc-select` to make sure solidity is version 0.8.19.

```bash
# remove previously installed solc, if any
sudo apt-get remove solc
pip3 install solc-select
```

```bash
solc-select use 0.8.19 --always-install
```

Install [Foundry](https://book.getfoundry.sh/getting-started/installation#using-foundryup):

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
# On the rare occasion the nightly commit of foundry has an issue you can install a fixed commit:
# foundryup --commit 8bbde620ab39246f3c89700a19dfe6f347e99f4f
```

Clone `axiom-v1-contracts` repository.

```bash
git clone https://github.com/axiom-crypto/axiom-v1-contracts.git
cd axiom-v1-contracts
forge install
```

## Deploy

### Deploy [AxiomTimelock](../../contracts/AxiomTimelock.sol)

Fill in [`timelock_constructor_args`](./timelock_constructor_args) with

```
<timelock minDelay in seconds> <timelock governance multisig address>
```

Then run

```bash
bash script/mainnet/deploy_axiom_timelock.sh
```

### Deploy SNARK verifier Yul contracts

The SNARK verifier contracts are auto-generated from Halo2 circuits using the [`snark-verifier`](https://github.com/axiom-crypto/snark-verifier) library. The code is currently in [Yul](https://docs.soliditylang.org/en/v0.8.19/yul.html). To deploy these to Ethereum, we need to compile them to EVM bytecode. The bytecode is stored in the [`snark-verifiers`](../../snark-verifiers/) directory as `*.bin` files.

One **should** compile them from source to check that the bytecode is correct. To do so, run the following command:

```bash
cd snark-verifiers
BYTE_CODE=$(solc --yul --bin mainnet_10_7.v1.yul | tail -1)
if [[ $BYTE_CODE == $(cat mainnet_10_7.v1.bin) ]]; then
    echo "Bytecode matches";
else
    echo "Bytecode does not match";
    exit 1
fi
BYTE_CODE=$(solc --yul --bin mainnet_17_7.v1.yul | tail -1)
if [[ $BYTE_CODE == $(cat mainnet_17_7.v1.bin) ]]; then
    echo "Bytecode matches";
else
    echo "Bytecode does not match";
    exit 1
fi
BYTE_CODE=$(solc --yul --bin batch_query_2.yul | tail -1)
if [[ $BYTE_CODE == $(cat batch_query_2.bin) ]]; then
    echo "Bytecode matches";
else
    echo "Bytecode does not match";
    exit 1
fi
```

This is done automatically in our [CI](../../.github/workflows/foundry.yml) to ensure that the bytecode is correct.

To deploy the contracts, run

```bash
bash script/mainnet/deploy_AxiomV1_snarkVerifier.sh
bash script/mainnet/deploy_AxiomV1_historicalVerifier.sh
bash script/mainnet/deploy_AxiomV1Query_mmrVerifier.sh
```

### Deploy Axiom implementation contracts

Our main contracts `AxiomV1` and `AxiomV1Query` follow a [Proxy Upgrade Pattern](https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies).
This means that we first deploy [UUPSUpgradeable](https://docs.openzeppelin.com/contracts/4.x/api/proxy#UUPSUpgradeable) implementation contracts _without_ initializing them:

```bash
bash script/mainnet/deploy_AxiomV1_implementation.sh
bash script/mainnet/deploy_AxiomV1Query_implementation.sh
```

### Deploy Axiom proxy contracts

After the implementation contracts are deployed, we record their deployed addresses in Forge scripts [`AxiomV1DeployMainnet.s.sol`](./AxiomV1DeployMainnet.s.sol) and [`AxiomV1QueryDeployMainnet.s.sol`](./AxiomV1QueryDeployMainnet.s.sol). We use these scripts to deploy [ERC1967Proxy](https://docs.openzeppelin.com/contracts/4.x/api/proxy#ERC1967Proxy)s that point to the implementation contracts:

```bash
bash script/mainnet/deploy_AxiomV1_proxy.sh
bash script/mainnet/deploy_AxiomV1Query_proxy.sh
```
