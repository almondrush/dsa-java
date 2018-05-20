package dsa;

import sun.security.jca.JCAUtil;

import java.math.BigInteger;
import java.security.SecureRandom;

public class DSAKeyGen {
    private static SecureRandom secureRandom = JCAUtil.getSecureRandom();

    public static DSAKeyPair generateKeys(DSAParams params) {
        L.i("Generating keys...");
        int qLength = params.getQ().bitLength();
        BigInteger x = new BigInteger(qLength / 2, secureRandom);
        if (x.compareTo(params.getQ()) > -1) {
            throw new RuntimeException("x is greater than q");
        }
        BigInteger y = params.getG().modPow(x, params.getP());


        L.i("Keys generated successfully");
        L.i("y = " + y);
        L.i("x = " + x);
        return new DSAKeyPair(x, y);
    }
}
