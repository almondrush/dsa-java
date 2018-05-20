package dsa;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class DSAParams {
    private BigInteger p;
    private BigInteger q;
    private BigInteger g;
    private BigInteger seed;
    private MessageDigest hash;

    public DSAParams(BigInteger p, BigInteger q, BigInteger g, BigInteger seed, MessageDigest hash) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.seed = seed;
        this.hash = hash;
    }

    public byte[] hash(byte[] input) {
        return hash.digest(input);
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getSeed() {
        return seed;
    }

    public void write(String filename) {
        try {
            Files.write(Paths.get(filename), new StringBuilder()
                    .append(p.toString()).append("\n")
                    .append(q.toString()).append("\n")
                    .append(g.toString()).append("\n")
                    .append(seed.toString()).append("\n")
                    .append(hash.getAlgorithm()).toString().getBytes()
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static DSAParams read(String filename) {
        try {
            List<String> lines = Files.readAllLines(Paths.get(filename));
            return new DSAParams(
                    new BigInteger(lines.get(0)),
                    new BigInteger(lines.get(1)),
                    new BigInteger(lines.get(2)),
                    new BigInteger(lines.get(3)),
                    MessageDigest.getInstance(lines.get(4))
            );
        } catch (IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public void printInfo() {
        L.i("=======================================================");
        L.i("DSA parameters");
        L.i("=======================================================");
        L.i("q = " + q);
        L.i("p = " + p);
        L.i("g = " + g);
        L.i("hash = " + hash.getAlgorithm());
        L.i("=======================================================\n\n\n");
    }
}
