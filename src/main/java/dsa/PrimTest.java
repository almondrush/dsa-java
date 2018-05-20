package dsa;

import java.math.BigInteger;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;


public class PrimTest {
    /**
     * Certainty of prime test. Probability of generated number being prime
     * is 1 - (1 / 2^CERTAINTY)
     */
    private static int CERTAINTY = 512;

    public static boolean test(BigInteger num) {
        if (CERTAINTY <= 0)
            return true;
        BigInteger w = num.abs();
        if (w.equals(BigInteger.valueOf(2)))
            return true;
        if (!w.testBit(0) || w.equals(BigInteger.ONE))
            return false;

        return primeToCertainty(num, null);
    }

    private static boolean primeToCertainty(BigInteger num, Random random) {
        int rounds = 0;
        int n = (Math.min(CERTAINTY, Integer.MAX_VALUE-1)+1)/2;

        int sizeInBits = num.bitLength();
        if (sizeInBits < 100) {
            rounds = 50;
            rounds = n < rounds ? n : rounds;
            return testMillerRabin(num, rounds, random);
        }

        if (sizeInBits < 256) {
            rounds = 27;
        } else if (sizeInBits < 512) {
            rounds = 15;
        } else if (sizeInBits < 768) {
            rounds = 8;
        } else if (sizeInBits < 1024) {
            rounds = 4;
        } else {
            rounds = 2;
        }
        rounds = n < rounds ? n : rounds;

        return testMillerRabin(num, rounds, random);
    }


    private static boolean testMillerRabin(BigInteger num, int iterations, Random rnd) {
        BigInteger numMinusOne = num.subtract(BigInteger.ONE);
        BigInteger m = numMinusOne;
        int a = m.getLowestSetBit();
        m = m.shiftRight(a);

        if (rnd == null) {
            rnd = ThreadLocalRandom.current();
        }
        for (int i=0; i < iterations; i++) {
            BigInteger b;
            do {
                b = new BigInteger(num.bitLength(), rnd);
            } while (b.compareTo(BigInteger.ONE) <= 0 || b.compareTo(num) >= 0);

            int j = 0;
            BigInteger z = b.modPow(m, num);
            while (!((j == 0 && z.equals(BigInteger.ONE)) || z.equals(numMinusOne))) {
                if (j > 0 && z.equals(BigInteger.ONE) || ++j == a)
                    return false;
                z = z.modPow(BigInteger.valueOf(2), num);
            }
        }
        return true;
    }
}
