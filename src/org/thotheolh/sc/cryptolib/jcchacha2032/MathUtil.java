/*
 * The 3-Clause BSD License
 *
 * Copyright 2019 Thotheolh 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the copyright holder nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 */

package org.thotheolh.sc.cryptolib.jcchacha2032;

import javacardx.framework.util.intx.JCint;

/**
 * The 32-bit Math library.
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