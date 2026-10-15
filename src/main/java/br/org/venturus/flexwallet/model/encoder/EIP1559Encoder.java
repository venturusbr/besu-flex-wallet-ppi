package br.org.venturus.flexwallet.model.encoder;

import br.org.venturus.flexwallet.crypto.AbstractSecp256;
import br.org.venturus.flexwallet.crypto.Secp256k1;
import br.org.venturus.flexwallet.model.Transaction;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.web3j.rlp.RlpEncoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpString;
import org.web3j.rlp.RlpType;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Encoder for standard EIP-1559 transactions (type 0x02).
 *
 * Unlike FlexibleEIP1559 (0x42), this encoder:
 * - does NOT include dsaType or publicKey fields in the RLP payload
 * - produces a classic ECDSA signature sliced from a 65-byte array:
 *     r = sig[0..31]
 *     s = sig[32..63]
 *     v = sig[64]
 *
 * This is used for benchmarking the unmodified Besu baseline, so that
 * throughput and latency metrics can be compared against the PQC variants.
 *
 * The signing curve must be the network's genesis ecCurve (secp256k1 unless
 * configured otherwise), since Besu recovers the sender on that curve.
 */
public class EIP1559Encoder extends TransactionEncoder {

    private final AbstractSecp256 ecdsa;
    private final boolean verbose;

    public EIP1559Encoder() {
        this(true);
    }

    public EIP1559Encoder(boolean verbose) {
        this(new Secp256k1(), verbose);
    }

    public EIP1559Encoder(AbstractSecp256 ecdsa, boolean verbose) {
        this.ecdsa = ecdsa;
        this.verbose = verbose;
    }

    /**
     * Encodes the transaction to RLP without dsaType/publicKey fields:
     *
     *   0x02 || RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
     *                gasLimit, to, value, data, accessList, v, r, s])
     */
    @Override
    public byte[] encodeToRlp(Transaction tx) {
        List<RlpType> values = asLegacyRlpValues(tx, tx.getSignature());
        RlpList rlpList = new RlpList(values);
        byte[] encoded = RlpEncoder.encode(rlpList);
        return ByteBuffer.allocate(encoded.length + 1)
                .put((byte) 0x02) // Standard EIP-1559 type
                .put(encoded)
                .array();
    }

    @Override
    public byte[] createRawTransaction(Transaction unsignedTx, PrivateKey sk) {
        byte[] digest = createDigest(unsignedTx);

        byte[] signature = ecdsa.sign(digest, sk);

        if (verbose) {
            System.out.println("~~~~~~~~~~~~~~~~~~~ Signature length ~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            System.out.println(signature.length);
            System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        }

        unsignedTx.setSignature(Optional.of(signature));
        return encodeToRlp(unsignedTx);
    }

    @Override
    public byte[] createDigest(Transaction unsignedTx) {
        byte[] encodedUnsignedTx = encodeToRlp(unsignedTx);
        Keccak.Digest256 keccak256 = new Keccak.Digest256();
        return keccak256.digest(encodedUnsignedTx);
    }

    /**
     * Builds the RLP field list for a standard EIP-1559 transaction.
     *
     * When no signature is present (unsigned), v/r/s are omitted — this is
     * the payload used for digest computation.
     *
     * When a 65-byte signature is present, it is sliced as:
     *   r = sig[0..31]
     *   s = sig[32..63]
     *   v = sig[64]
     */
    private List<RlpType> asLegacyRlpValues(Transaction tx, Optional<byte[]> signature) {
        List<RlpType> result = new ArrayList<>();

        result.add(RlpString.create(tx.getChainId()));
        result.add(RlpString.create(tx.getNonce()));
        result.add(RlpString.create(tx.getMaxPriorityFeePerGas()));
        result.add(RlpString.create(tx.getMaxFeePerGas()));
        result.add(RlpString.create(tx.getGasLimit()));

        String to = tx.getTo();
        if (to != null && !to.isEmpty()) {
            result.add(RlpString.create(Numeric.hexStringToByteArray(to)));
        } else {
            result.add(RlpString.create(""));
        }

        result.add(RlpString.create(tx.getValue()));
        result.add(RlpString.create(Numeric.hexStringToByteArray(tx.getData())));
        result.add(new RlpList(tx.rlpAccessList()));

        signature.ifPresent(sig -> {
            if (sig.length != 65) {
                throw new IllegalArgumentException(
                    "Expected 65-byte ECDSA signature, got " + sig.length);
            }
            byte[] r = Arrays.copyOfRange(sig,  0, 32);
            byte[] s = Arrays.copyOfRange(sig, 32, 64);
            byte   v = sig[64];

            result.add(RlpString.create(Byte.toUnsignedInt(v)));      // v como escalar
            result.add(RlpString.create(new BigInteger(1, r)));        // r como BigInteger
            result.add(RlpString.create(new BigInteger(1, s)));        // s como BigInteger
        });

        return result;
    }
}