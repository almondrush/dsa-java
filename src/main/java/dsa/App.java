package dsa;

import java.util.logging.Level;
import java.util.logging.Logger;

public class App {
    private static String PARAMS_FILE = "params.dsap";
    private static String KEY_FILE = "key.dsak";

    public static void main(String[] args) {
        try {
//            DSAParams params = new DSAParamsGen.Builder()
//                    .withSHA256()
//                    .build();

//            params.write(PARAMS_FILE);

            DSAParams params = DSAParams.read(PARAMS_FILE);
            params.printInfo();

//            DSAKeyPair key = DSAKeyGen.generateKeys(params);
//            key.write(KEY_FILE);

            DSAKeyPair key = DSAKeyPair.read(KEY_FILE);
            key.printInfo();

//============================================================================

            DSA dsa = new DSA(params);

            String message = "Hello world!";

            DSA.Sign sign = dsa.sign(message, key);

            boolean valid = dsa.check(message, sign, key.getY());

            System.out.println("Valid: " + valid);

        } catch (Throwable e) {
            Logger.getLogger("DSA").log(Level.WARNING, "Exception:", e);
        }
    }
}
