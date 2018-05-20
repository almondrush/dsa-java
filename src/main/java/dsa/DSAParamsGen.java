package dsa;

import sun.security.jca.JCAUtil;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;

public abstract class DSAParamsGen {
    private static SecureRandom secureRandom = JCAUtil.getSecureRandom();

    private static DSAParams generateDSAParams(int pBitLength, int qBitLength,
                                       MessageDigest hash, SecureRandom secureRandom) {
        L.i("Generating DSA Parameters...");
        long start = System.currentTimeMillis();
        /* 1 */
        int l_ = pBitLength; // The desired length of prime p
        L.i("L = " + l_);
        int n_ = qBitLength; // The desired length of prime q
        L.i("N = " + n_);
        /* 2 */
        int seedLength = qBitLength; // The desired length of the domain parameter seed
        L.v("Seed length = " + seedLength);

        int digestBitLength = hash.getDigestLength() * 8;

        /* 3 */
        int n = (int) (Math.ceil((float) l_ / (float) digestBitLength) - 1);
        L.v("n = " + n);

        /* 4 */
        int b = l_ - 1 - (n * digestBitLength);
        L.v("b = " + b);


        BigInteger seed = null;
        BigInteger q = null;
        BigInteger p = null;
        BigInteger g;
        boolean qIsPrime;
        while (p == null) {
            do {
                /* 5 */
                seed = new BigInteger(seedLength, secureRandom);
                L.v("Seed = " + seed);

                q = generateQ(seed, n_, hash);

                L.v("q = " + q);
                L.v("q bit length = " + q.bitLength());
                /* 8 */
                qIsPrime = PrimTest.test(q);
                /* 9 */
            } while (!qIsPrime); // If q is not prime, go to step 5

            L.v("\n\n\n");
            L.v("Prime q is FOUND\n");
            L.v("q = " + q);
            L.v("q bit length = " + q.bitLength());
            L.v("\n\n\n");

            p = generateP(q, n, seed, seedLength, l_, b, digestBitLength, hash);
        }

        g = generateG(q, p, pBitLength);

        L.i("DSA parameters successfully generated.");

        L.i("q = " + q);
        L.v("length: " + q.bitLength());
        L.i("p = " + p);
        L.v("length: " + p.bitLength());
        L.i("g = " + g);
        L.v("length: " + g.bitLength());
        long end = System.currentTimeMillis();
        L.i("Estimated time: " + (end - start) + "ms.");

        return new DSAParams(p, q, g, seed, hash);
    }

    private static BigInteger generateQ(BigInteger seed, int n_, MessageDigest hash) {
        /* 6 */
        // U = hash(seed) mod 2^(N - 1)
        BigInteger u_ = new BigInteger(1, hash.digest(seed.toByteArray()))
                .mod(BigInteger.valueOf(2).pow(n_ - 1));

        L.v("U = " + u_);
        L.v("U bit length = " + u_.bitLength());

        /* 7 */
        // q = 2^(N - 1) + U + 1 - (U mod 2)
        return BigInteger.valueOf(2).pow(n_ - 1)
                .add(u_)
                .add(BigInteger.valueOf(1))
                .subtract(u_.mod(BigInteger.valueOf(2)));
    }

    private static BigInteger generateP(BigInteger q, int n, BigInteger seed, int seedLength,
                                 int l_, int b, int digestBitLength, MessageDigest hash) {
        /* 10 */
        int offset = 1;

        /* 11 */
        ArrayList<BigInteger> v_ = new ArrayList<>();
        for (int counter = 0; counter < 4 * l_ - 1; counter++) {

            /* 11.1 */
            for (int j = 0; j <= n; j++) {
                //V[j] = hash((seed + offset + j) mod 2^seedlength)

                BigInteger tmp = seed
                        .add(BigInteger.valueOf(offset))
                        .add(BigInteger.valueOf(j))
                        .mod(BigInteger.valueOf(2).pow(seedLength));

                byte[] digest = hash.digest(tmp.toByteArray());

                v_.add(new BigInteger(1, digest));
            }

            /* 11.2 */
            // W = { sum(V[i] * 2^outlen * i) for i in 0..n - 1 } + (V[n] mod 2^b) * 2^(outlen * n)
            BigInteger w_ = BigInteger.ZERO;
            for (int i = 0; i <= n; i++) {
                BigInteger tmp = v_.get(i);

                if (i == n) tmp = tmp.mod(BigInteger.valueOf(2).pow(b));

                tmp = tmp.shiftLeft(digestBitLength * i);

                w_ = w_.add(tmp);
            }
            L.v("W = " + w_);
            L.v("W bit length = " + w_.bitLength());

            // 0 <= W <= 2^(L - 1)
            if (w_.compareTo(BigInteger.valueOf(2).pow(l_ - 1)) > 0) {
                throw new RuntimeException("W is greater than 2^(L - 1)");
            }

            /* 11.3 */
            // X = W + 2^(L - 1)
            BigInteger x_ = w_.add(BigInteger.valueOf(2).pow(l_ - 1));
            L.v("X = " + x_);
            L.v("X bit length = " + x_.bitLength());

            /* 11.4 */
            // c = X mod 2q
            BigInteger c = x_.mod(BigInteger.valueOf(2).multiply(q));
            L.v("c = " + c);
            L.v("c bit length = " + c.bitLength());

            /* 11.5 */
            // p = X - (c - 1)
            BigInteger p = x_.subtract(c.subtract(BigInteger.ONE));
            L.v("p = " + p);
            L.v("p bit length = " + p.bitLength());


            if (p.subtract(BigInteger.ONE).remainder(q).compareTo(BigInteger.ZERO) != 0) {
                throw new RuntimeException("Incorrect p. The q is not a divider of p - 1.");
            }

            /* 11.6 */
            boolean pIsPrime;
            if (p.compareTo(BigInteger.valueOf(2).pow(l_ - 1)) > -1) {
                L.v("p is greater than 2^(L - 1). Checking primality...");
                /* 11.7 */
                pIsPrime = PrimTest.test(p);
                /* 11.8 */
                if (pIsPrime) {
                    L.v("\n\n\n");
                    L.v("Prime p is FOUND\n");
                    L.v("p = " + p);
                    L.v("p bit length = " + p.bitLength());
                    L.v("\n\n\n");

                    return p;
                } else {
                    L.v("p is not prime. Continue searching...");
                }
            } else {
                L.v("p is not long enough. Continue searching...");
            }
            /* 11.9 */
            offset = offset + n + 1;
            L.v("Set offset to " + offset);
        }
        return null;
    }

    private static BigInteger generateG(BigInteger q, BigInteger p, int pBitLength) {
        int hBitLen = pBitLength / 2;
        BigInteger h;
        BigInteger g;
        do {
            h = new BigInteger(hBitLen, secureRandom);
            if (h.compareTo(p.subtract(BigInteger.ONE)) > -1) {
                throw new RuntimeException("hash is greater than p - 1");
            }
            BigInteger exp = p.subtract(BigInteger.ONE).divide(q);
            g = h.modPow(exp, p);
        } while (g.compareTo(BigInteger.ONE) <= 0);
        return g;
    }

    public static class Builder {
        private MessageDigest hash;
        private int pBitLength = 512;
        private int qBitLength = 160;

        public DSAParams build() {
            if (pBitLength < 512 || pBitLength > 3072 || pBitLength % 64 != 0) {
                throw new IllegalArgumentException("Bit length of p is illegal: " +
                        "it must be a number between 512 and 3072 and divide by 64 " +
                        "without a reminder.");
            }
            if (qBitLength < 160 || qBitLength > hash.getDigestLength() * 8) {
                throw new IllegalArgumentException("Bit length of q is illegal: " +
                        "it must be a number between 160 and 256 and not greater " +
                        "than selected hash function digest size. Current length of q: "
                        + qBitLength + ", length of digest: " + hash.getDigestLength() * 8);
            }
            if (hash == null) {
                throw new RuntimeException("Cannot build dsa.DSA. Hash function is not selected.");
            }
            return generateDSAParams(pBitLength, qBitLength, hash, secureRandom);
        }

        public Builder pBitLength(int pBitLength) {
            this.pBitLength = pBitLength;
            return this;
        }

        public Builder qBitLength(int qBitLength) {
            this.qBitLength = qBitLength;
            return this;
        }

        public Builder withSHA1() {
            if (hash != null) throw new RuntimeException("Hash function is already set");
            try {
                hash = MessageDigest.getInstance("SHA1");
            } catch (Throwable e) {
                throw new RuntimeException(e);
            }
            return this;
        }

        public Builder withSHA224() {
            if (hash != null) throw new RuntimeException("Hash function is already set");
            try {
                hash = MessageDigest.getInstance("SHA-244");
            } catch (Throwable e) {
                throw new RuntimeException(e);
            }
            return this;
        }

        public Builder withSHA256() {
            if (hash != null) throw new RuntimeException("Hash function is already set");
            try {
                hash = MessageDigest.getInstance("SHA-256");
            } catch (Throwable e) {
                throw new RuntimeException(e);
            }
            return this;
        }
    }
}
