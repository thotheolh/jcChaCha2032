/*
 * 32 bit Math in 8 bit format.
 */
package org.thotheolh.sc.cryptolib.jcchacha2032;

import javacardx.framework.util.intx.JCint;

/**
 *
 * @author Thotheolh
 */
public class MathUtil {


    public static void mod32Add(byte[] a, short aOffset, byte[] b, short bOffset, byte[] result, short offset) {
        JCint.setInt(result, offset, JCint.getInt(a, aOffset) + JCint.getInt(b, bOffset));
    }

    public static void xor32(byte[] a, short aOffset, byte[] b, short bOffset, byte[] result, short offset) {
        JCint.setInt(result, offset, JCint.getInt(a, aOffset) ^ JCint.getInt(b, bOffset));
    }

    public static void rotl32(byte[] a, short offset, short amt, int buff1) {
        buff1 = JCint.getInt(a, offset);
        JCint.setInt(a, offset, ((buff1 << amt) | (buff1 >>> (32 - (int) amt))));
    }
}