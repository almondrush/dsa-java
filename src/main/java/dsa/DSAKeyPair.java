package dsa;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class DSAKeyPair {
    private BigInteger x;
    private BigInteger y;

    public DSAKeyPair(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    public BigInteger getX() {
        return x;
    }

    public BigInteger getY() {
        return y;
    }

    public void write(String filename) {
        try {
            Files.write(Paths.get(filename), new StringBuilder()
                    .append(x.toString()).append("\n")
                    .append(y.toString()).append("\n")
                    .toString().getBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static DSAKeyPair read(String filename) {
        try {
            List<String> lines = Files.readAllLines(Paths.get(filename));
            return new DSAKeyPair(
                    new BigInteger(lines.get(0)),
                    new BigInteger(lines.get(1)));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void printInfo() {
        L.i("=======================================================");
        L.i("DSA key");
        L.i("=======================================================");
        L.i("x = " + x);
        L.i("y = " + y);
        L.i("=======================================================\n\n\n");
    }
}
