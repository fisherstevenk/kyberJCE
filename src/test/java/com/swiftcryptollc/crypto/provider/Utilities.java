package com.swiftcryptollc.crypto.provider;

/**
 * Simply utility class to "pretty print" some arrays for testing purposes
 *
 * @author Steven K Fisher <swiftcryptollc@gmail.com>
 */
public class Utilities {

    /**
     * Print a byte array on one line
     *
     * @param name
     * @param array
     */
    public static void printByteArray(String name, byte[] array) {
        System.out.print(name + " " + array.length + " [");
        for (int i = 0; i < array.length; ++i) {
            System.out.print(" " + (int) (array[i] & 0xFF));
        }
        System.out.println("]");
    }

    public static void printBinaryArray(String name, byte[] array) {
        //     System.out.print(name + " " + array.length + " [");
        System.out.print("[");
        for (int i = 0; i < array.length; ++i) {
            String s1 = String.format("%8s", Integer.toBinaryString(array[i] & 0xFF)).replace(' ', '0');
            System.out.print(s1 + " ");
        }
        System.out.println("]");
    }

    /**
     * Print a short array on one line
     *
     * @param name
     * @param array
     */
    public static void printShortArray(String name, short[] array) {
        System.out.print(name + " " + array.length + " [");
        for (int i = 0; i < array.length; ++i) {
            System.out.print(" " + array[i]);
        }
        System.out.println("]");
    }

    /**
     * Print out a double short array
     *
     * @param name
     * @param array
     */
    public static void printShortArray(String name, short[][] array) {
        for (int i = 0; i < array.length; ++i) {
            System.out.print(name + " " + array[i].length + " [");
            int zero = 0;
            for (int j = 0; j < array[i].length; ++j) {
                System.out.print(" " + array[i][j]);
                if (array[i][j] == 0) {
                    zero++;
                }
            }
            System.out.println("] " + zero);
        }
    }

    /**
     * Test to compare the equality of two byte arrays
     *
     * Returns 0 if they are equal
     *
     * @param x
     * @param y
     * @return
     */
    public static int constantTimeCompare(byte[] x, byte[] y) {
        if (x.length != y.length) {
            return 1;
        }

        byte v = 0;

        for (int i = 0; i < x.length; i++) {
            v = (byte) ((int) (v & 0xFF) | ((int) (x[i] & 0xFF) ^ (int) (y[i] & 0xFF)));
        }
        return Byte.compare(v, (byte) 0);
    }
}
