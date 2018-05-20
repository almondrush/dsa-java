package dsa;

public class L {
    static boolean verbose = false;

    public static void i(Object msg) {
        System.out.println("[INFO] " + msg.toString());
    }
    public static void v(Object msg) {
        if (verbose) System.out.println("[VERBOSE] " + msg.toString());
    }
}
