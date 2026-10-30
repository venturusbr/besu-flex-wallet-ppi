# besu-flex-wallet-ppi

A minimal Java CLI wallet that signs and submits transactions to a (modified) Besu network. Built to test the DSA-agnostic transaction protocol — sending `FlexibleEIP1559` transactions signed with hybrid post-quantum schemes (ECDSA/secp256k1 + ML-DSA-44 or Falcon-512 via Strong Nesting Concatenation) — and also capable of producing plain `EIP1559` transactions (on secp256k1 or secp256r1, see `--ecCurve`) for comparison against stock Besu.

## Requirements

- Java 21
- Maven 3.x
- A running Besu network exposing JSON-RPC (the modified Besu for `FlexibleEIP1559`; stock Besu works for `EIP1559`)

## Build

```sh
mvn clean install
```

## Quick start

Send a single `FlexibleEIP1559` transaction to `http://localhost:8545`:

```sh
mvn exec:java -Dexec.args="--txType FlexibleEIP1559"
```

Send 100 `FlexibleEIP1559` transactions in parallel across the four default nodes (`localhost:8545`–`8548`), each from its own freshly generated account:

```sh
mvn exec:java -Dexec.args="--txAmount 100 --txType FlexibleEIP1559"
```

Show all flags and examples:

```sh
mvn exec:java -Dexec.args="--help"
```

## Modes

The wallet runs in one of two modes, chosen by the presence of `--txAmount`:

- **Single-tx mode** (default) — signs one transaction with nonce 0 using the key pair from the key file and prints the raw JSON-RPC response to stdout.
- **Batch mode** (`--txAmount N`) — generates N fresh key pairs in memory and sends one transaction from each, in parallel, distributed round-robin across the configured endpoints. Every transaction has its own sender address and nonce 0. The key file is not read or written, and the generated keys are discarded when the run ends. A live progress line is updated every 500 ms while running, and every outcome (success or failure) is written to a CSV at the end together with a summary on stdout.

## Arguments

All flags are case-insensitive and accept either the `--flag value` or `--flag=value` form.

- **`--help`, `-h`** — Print the full usage block and exit. Works without any other setup, so it's safe to run on a fresh clone before generating keys.

- **`--generateKeys`** — Force regeneration of the key pair file. Without this flag, keys are only created if the file is missing. ⚠️ Using `--generateKeys` overwrites any existing key file. Ignored in batch mode, which never uses the key file.

- **`--txAmount N`** — Enable batch mode. Sends `N` transactions in parallel, each from a freshly generated account with nonce 0. Without this flag the app sends a single transaction with nonce 0 from the key-file account.

- **`--nodes URL1,URL2,...`** — Comma-separated JSON-RPC endpoints. In batch mode, transactions are distributed across them round-robin by transaction index; in single-tx mode only the first URL is used. Defaults: `http://localhost:8545,http://localhost:8546,http://localhost:8547,http://localhost:8548` in batch mode, `http://localhost:8545` in single-tx mode.

- **`--output PATH`** — CSV output path for batch mode. Defaults to `tx_results_<yyyyMMdd-HHmmss>.csv` in the current working directory. Ignored in single-tx mode.

- **`--maxRate TPS`** — Upper bound on the batch submission rate, in transactions per second. Fractional values are allowed (`0.5` = one tx every 2 seconds). When omitted, the submission loop runs as fast as the worker pool can dispatch — which can flood a co-located Besu's tx pool faster than consensus can drain it. Pick a value that matches your block time × txs-per-block budget. Ignored in single-tx mode.

- **`--txType TYPE`** *(required)* — Transaction type to build. Either `EIP1559` (standard Ethereum, ECDSA signature) or `FlexibleEIP1559` (hybrid signature, see `--hybridDsa`).

- **`--hybridDsa NAME`** — Hybrid signature scheme for `FlexibleEIP1559` transactions. Ignored for `EIP1559`.
  - `SECP256K1-MLDSA44` *(default)* — secp256k1 + ML-DSA-44, `dsaType` `0x0060`.
  - `SECP256K1-FALCON512` — secp256k1 + Falcon-512, `dsaType` `0x0070`.

  In both cases secp256k1 signs the digest first and the PQC algorithm signs `digest || secp256k1Signature`. The transaction carries only the PQC public key, because Besu recovers the secp256k1 key from its signature. Falcon signatures are variable-length (~650–670 bytes). The single-tx key file holds one hybrid key pair, so pass `--generateKeys` when switching schemes. The wallet refuses to sign with a key file generated for the other scheme.

- **`--ecCurve NAME`** — Curve that signs `EIP1559` transactions. Ignored for `FlexibleEIP1559`.
  - `secp256k1` *(default)* — stock Ethereum.
  - `secp256r1` — for networks whose genesis sets `"ecCurve": "secp256r1"`, such as besu-qbft's `init-qbft.sh --node-dsa=SECP256R1`.

  It must match the network's genesis `ecCurve`. Besu recovers the sender of an `EIP1559` transaction on that curve. A signature made on the other curve is either rejected with the JSON-RPC error `-32002 Invalid signature` (counted as a failed transaction) or, worse, accepted from a meaningless sender address. The single-tx key file holds one key pair, so pass `--generateKeys` when switching curves. The wallet refuses to sign with a key file generated for another curve. In single-tx mode the wallet prints the sender address.

## Examples

Single `FlexibleEIP1559` transaction to `localhost:8545`:

```sh
mvn exec:java -Dexec.args="--txType FlexibleEIP1559"
```

100 legacy `EIP1559` transactions across the 4 default nodes:

```sh
mvn exec:java -Dexec.args="--txAmount 100 --txType EIP1559"
```

1,000 `EIP1559` transactions to a secp256r1 network (besu-qbft `init-qbft.sh --node-dsa=SECP256R1`):

```sh
mvn exec:java -Dexec.args="--txAmount 1000 --txType EIP1559 --ecCurve secp256r1"
```

10,000 `FlexibleEIP1559` transactions with a custom CSV path:

```sh
mvn exec:java -Dexec.args="--txAmount 10000 --output /tmp/run42.csv --txType FlexibleEIP1559"
```

Generate fresh keys, then send a single `FlexibleEIP1559` transaction signed with secp256k1 + Falcon-512:

```sh
mvn exec:java -Dexec.args="--generateKeys --txType FlexibleEIP1559 --hybridDsa SECP256K1-FALCON512"
```

1,000 `FlexibleEIP1559` transactions distributed across two specific nodes:

```sh
mvn exec:java -Dexec.args="--txAmount 1000 --nodes http://node1:8545,http://node2:8545 --txType FlexibleEIP1559"
```

10,000 `FlexibleEIP1559` transactions, capped at 20 TPS — gentle on a co-located QBFT node so the tx pool does not fill faster than consensus drains it:

```sh
mvn exec:java -Dexec.args="--txAmount 10000 --maxRate 20 --txType FlexibleEIP1559"
```

## CSV output

In batch mode, every transaction outcome is written to a CSV with the following columns:

- `nonce` — Despite the name, the 0-based transaction index within the batch (`-1` if the worker task crashed). The on-chain nonce of every batch transaction is 0.
- `endpoint` — The JSON-RPC URL the transaction was POSTed to.
- `status` — `success` or `failure`.
- `txHash` — Transaction hash returned by the node on success; empty on failure.
- `errorMessage` — JSON-RPC `error.message` or the local exception message; empty on success.
- `elapsedMs` — Per-transaction build + sign + POST time in milliseconds.
- `timestamp` — ISO-8601 instant of when the request started.

The console summary at the end shows totals, total elapsed time, average rate, a per-endpoint breakdown (`ok` / `fail` / `total`) and a count of failures grouped by error message — useful for spotting a flaky node or a single-cause spike at a glance.

## Operational notes

- **One fresh account per batch transaction.** Because every sender is new and sends exactly one transaction with nonce 0, batch runs never hit `nonce too low` or nonce gaps, and the per-sender tx-pool limits on the Besu side do not apply. The generated accounts are unfunded, so this relies on the zero gas price the wallet uses (`maxFeePerGas` = 0). Key generation happens up front, so large `--txAmount` values with hybrid schemes take a noticeable time before the first transaction is sent.
- **Single-tx mode always uses nonce 0.** Sending a second single transaction from the same key-file account fails with `nonce too low`. Pass `--generateKeys` to switch to a new account.
- **Tx-pool sizing on the Besu side.** For large batches the total pool size, not the per-sender limit, is the constraint. Raise `tx-pool-max-size` on every node (e.g. `tx-pool-max-size=20000`) or cap the submission rate with `--maxRate`.
- **Throughput tuning.** The worker pool defaults to 16 threads and the HTTP client to 32 connections per endpoint. When pushing high `--maxRate` against a small number of nodes, raise these constants in `BatchRunner.java` (`DEFAULT_CONCURRENCY`) and `EthSendRawTransaction.java` (`MAX_CONNECTIONS_PER_ROUTE` / `MAX_TOTAL_CONNECTIONS`).
- **Single endpoint, high concurrency.** With only one URL in `--nodes` and `--txAmount` larger than the per-route HTTP pool size, requests serialize on connection acquisition rather than at Besu. Spread the load with more endpoints, or raise the pool size.
