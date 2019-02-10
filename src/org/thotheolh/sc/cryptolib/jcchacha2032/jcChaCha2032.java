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

import javacard.framework.*;
import javacardx.framework.util.intx.JCint;

/**
 * Please ensure your JavaCard have 32-bit math integer support. Ask the card
 * supplier whom you have purchased your JavaCard from before using these codes
 * otherwise it wouldn't work on your JavaCard smart card.
 *
 * @author Thotheolh
 */
public class jcChaCha2032 extends Applet {

    private short[] sBuff = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_RESET);
    private byte[] nonce = JCSystem.makeTransientByteArray((short) 12, JCSystem.CLEAR_ON_RESET);
    private byte[] counter = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_RESET);
    private byte[] key = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_RESET);
    private byte[] b1 = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_RESET);
    private byte[] b2 = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_RESET);
    private static ChaCha20 cipher;

    /**
     * Installs this applet.
     *
     * @param bArray
     * the array containing installation parameters
     * @param bOffset
     * the starting offset in bArray
     * @param bLength
     * the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new jcChaCha2032();
        cipher = new ChaCha20();
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected jcChaCha2032() {
        register();
    }

    /**
     * Processes an incoming APDU.
     *
     * @see APDU
     * @param apdu
     * the incoming APDU
     */
    public void process(APDU apdu) {
        //Insert your code here

        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        // CLA = 00, INS = DA (PUT DATA)
        if (buffer[ISO7816.OFFSET_CLA] == (byte) 0x00) {
            if (buffer[ISO7816.OFFSET_INS] == (byte) 0xDA) {

                /**
                 * Input APDU Data Structure
                 * -------------------------
                 *
                 * +------------+-------------+----------+---------------+
                 * | Nonce (12) | Counter (4) | Key (32) | Message (208) |
                 * +------------+-------------+----------+---------------+
                 *
                 */
                if (buffer[ISO7816.OFFSET_P1] == (byte) 0x01) {
                    if ((buffer[ISO7816.OFFSET_LC] & 0xFF) > 48) {

                        // Copy nonce
                        Util.arrayCopyNonAtomic(buffer, (short) 5, nonce, (short) 0, (short) 12);

                        // Copy counter
                        Util.arrayCopyNonAtomic(buffer, (short) 17, counter, (short) 0, (short) 4);

                        // Copy key
                        Util.arrayCopyNonAtomic(buffer, (short) 21, key, (short) 0, (short) 32);

                        // Calculate message length
                        sBuff[0] = (short) ((buffer[ISO7816.OFFSET_LC] & 0xFF) - 48);

                        // Copy incoming message
                        Util.arrayCopyNonAtomic(buffer, (short) 53, b1, (short) 0, (short) sBuff[0]);

                        /**
                         * Encrypt in loops of 64 bytes with sBuff[0] storing a
                         * decrementing counter to keep track of number of
                         * remaining bytes needing processing while sBuff[1]
                         * stores an upwards incrementing counter to keep track
                         * of the number of bytes already processed.
                         */
                        while (sBuff[0] > 0) {

                            /**
                             * Need to only process less than or equals to 64
                             * bytes and also finalizes the processing by
                             * breaking the while loop via setting the sBuff[0]
                             * to 0.
                             */
                            if (sBuff[0] <= 64) {
                                cipher.encrypt(key, (short) 0, nonce, (short) 0, counter, (short) 0, b1, sBuff[1], (short) ((buffer[ISO7816.OFFSET_LC] & 0xFF) - 48 - sBuff[1]), b2, sBuff[1]);

                                // Increment length of processed bytes
                                sBuff[1] += sBuff[0];

                                // Reset loop counter
                                sBuff[0] = 0;
                            } else {
                                cipher.encrypt(key, (short) 0, nonce, (short) 0, counter, (short) 0, b1, (short) 0, (short) 64, b2, sBuff[1]);

                                // Decrement remainder bytes counter
                                sBuff[0] -= 64;

                                // Increment already processed bytes counter
                                sBuff[1] += 64;

                                // Increment ChaCha20's counter while using the b2 array that stores cryptographic result as the carry counter
                                increment(counter, (short) 0);
                            }
                        }

                        // Send out response of encrypted ciphertext
                        apdu.setOutgoing();
                        apdu.setOutgoingLength(sBuff[1]);
                        apdu.sendBytesLong(b2, (short) 0, sBuff[1]);

                        // Reset output amount counter
                        sBuff[1] = 0;
                    }
                } else if (buffer[ISO7816.OFFSET_P1] == (byte) 0x02) {

                    // Decrypt
                    if ((buffer[ISO7816.OFFSET_LC] & 0xFF) > 48) {

                        // Copy nonce
                        Util.arrayCopyNonAtomic(buffer, (short) 5, nonce, (short) 0, (short) 12);

                        // Copy counter
                        Util.arrayCopyNonAtomic(buffer, (short) 17, counter, (short) 0, (short) 4);

                        // Copy key
                        Util.arrayCopyNonAtomic(buffer, (short) 21, key, (short) 0, (short) 32);

                        // Calculate message length
                        sBuff[0] = (short) ((buffer[ISO7816.OFFSET_LC] & 0xFF) - 48);

                        // Copy incoming message
                        Util.arrayCopyNonAtomic(buffer, (short) 53, b1, (short) 0, (short) sBuff[0]);

                        /**
                         * Decrypt in loops of 64 bytes with sBuff[0] storing a
                         * decrementing counter to keep track of number of
                         * remaining bytes needing processing while sBuff[1]
                         * stores an upwards incrementing counter to keep track
                         * of the number of bytes already processed.
                         */
                        while (sBuff[0] > 0) {

                            /**
                             * Need to only process less than or equals to 64
                             * bytes and also finalizes the processing by
                             * breaking the while loop via setting the sBuff[0]
                             * to 0.
                             */
                            if (sBuff[0] <= 64) {
                                cipher.decrypt(key, (short) 0, nonce, (short) 0, counter, (short) 0, b1, sBuff[1], (short) ((buffer[ISO7816.OFFSET_LC] & 0xFF) - 48 - sBuff[1]), b2, sBuff[1]);

                                // Increment length of processed bytes
                                sBuff[1] += sBuff[0];

                                // Reset loop counter
                                sBuff[0] = 0;
                            } else {
                                cipher.decrypt(key, (short) 0, nonce, (short) 0, counter, (short) 0, b1, (short) 0, (short) 64, b2, sBuff[1]);

                                // Decrement remainder bytes counter
                                sBuff[0] -= 64;

                                // Increment already processed bytes counter
                                sBuff[1] += 64;

                                // Increment ChaCha20's counter while using the b2 array that stores cryptographic result as the carry counter
                                increment(counter, (short) 0);
                            }
                        }

                        // Send out response of encrypted ciphertext
                        apdu.setOutgoing();
                        apdu.setOutgoingLength(sBuff[1]);
                        apdu.sendBytesLong(b2, (short) 0, sBuff[1]);

                        // Reset output amount counter
                        sBuff[1] = 0;
                    }
                } else {
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                }
            } else {
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } else {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    public void increment(byte[] bCtrArray, short offset) {
        JCint.setInt(bCtrArray, offset, JCint.getInt(bCtrArray, offset) + 1);
    }
}
