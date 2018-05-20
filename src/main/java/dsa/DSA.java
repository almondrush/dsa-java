package dsa;

import sun.security.jca.JCAUtil;

import java.math.BigInteger;
import java.security.SecureRandom;

public class DSA {

    // Secure random from Java Cryptography Architecture
    private static SecureRandom secureRandom = JCAUtil.getSecureRandom();

    private DSAParams params;

    public DSA(DSAParams params) {
        this.params = params;
    }

    public DSA.Sign sign(String message, DSAKeyPair key) {
        L.v("Signing message...");
        BigInteger r;
        BigInteger k;
        BigInteger s;
        BigInteger hash;
        BigInteger kInv;
        do {
            do {
//                k = new BigInteger(params.getQ().bitLength() / 2, secureRandom);
                k = BigInteger.valueOf(3);
                r = (params.getG().modPow(k, params.getP()))
                        .mod(params.getQ());

            } while (r.equals(BigInteger.ZERO));

            kInv = k.modInverse(params.getQ());

            hash = new BigInteger(1, params.hash(message.getBytes()));

            s = hash
                    .add(key.getX().multiply(r))
                    .multiply(kInv)
                    .mod(params.getQ());
        } while (s.equals(BigInteger.ZERO));
        L.v("k = " + k);
        L.v("Hash = " + hash);
        L.v("Message signed successfully.");
        L.v("r = " + r);
        L.v("s = " + s);
        return new Sign(r, s);
    }

    public boolean check(String message, DSA.Sign sign, BigInteger pubKey) {
        L.v("Checking message sign...");
        BigInteger y = pubKey;
        BigInteger w = sign.getS().modInverse(params.getQ());

        BigInteger hash = new BigInteger(1, params.hash(message.getBytes()));

        BigInteger u1 = hash
                .multiply(w)
                .mod(params.getQ());
        L.v("u1 = " + u1);

        BigInteger u2 = sign.getR()
                .multiply(w)
                .mod(params.getQ());
        L.v("u2 = " + u2);


        BigInteger a = params.getG().modPow(u1, params.getP());
        BigInteger b = y.modPow(u2, params.getP());
        BigInteger c = a.multiply(b).mod(params.getP());

        BigInteger v = c.mod(params.getQ());
        L.v("v = " + v);
        return v.equals(sign.getR());
    }

    public static class Sign {
        private BigInteger r;
        private BigInteger s;

        public Sign(BigInteger r, BigInteger s) {
            this.r = r;
            this.s = s;
        }

        public BigInteger getR() {
            return r;
        }

        public BigInteger getS() {
            return s;
        }
    }
}
