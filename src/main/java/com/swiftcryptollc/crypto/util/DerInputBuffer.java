/*
 * Copyright (c) 1996, 2017, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
package com.swiftcryptollc.crypto.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * DER input buffer ... this is the main abstraction in the DER library which
 * actively works with the "untyped byte stream" abstraction. It does so with
 * impunity, since it's not intended to be exposed to anyone who could violate
 * the "typed value stream" DER model and hence corrupt the input stream of DER
 * values.
 *
 * @author David Brownell
 */
class DerInputBuffer extends ByteArrayInputStream implements Cloneable {

    boolean allowBER = true;

    DerInputBuffer(byte[] buf, boolean allowBER) {
        super(buf);
        this.allowBER = allowBER;
    }

    DerInputBuffer(byte[] buf, int offset, int len, boolean allowBER) {
        super(buf, offset, len);
        this.allowBER = allowBER;
    }

    DerInputBuffer dup() {
        try {
            DerInputBuffer retval = (DerInputBuffer) clone();
            retval.mark(Integer.MAX_VALUE);
            return retval;
        } catch (CloneNotSupportedException e) {
            throw new IllegalArgumentException(e.toString());
        }
    }

    byte[] toByteArray() {
        int len = available();
        if (len <= 0) {
            return null;
        }
        byte[] retval = new byte[len];

        System.arraycopy(buf, pos, retval, 0, len);
        return retval;
    }

    int peek() throws IOException {
        if (pos >= count) {
            throw new IOException("out of data");
        } else {
            return buf[pos];
        }
    }

    /**
     * Compares this DerInputBuffer for equality with the specified object.
     */
    public boolean equals(Object other) {
        if (other instanceof DerInputBuffer) {
            return equals((DerInputBuffer) other);
        } else {
            return false;
        }
    }

    boolean equals(DerInputBuffer other) {
        if (this == other) {
            return true;
        }

        int max = this.available();
        if (other.available() != max) {
            return false;
        }
        for (int i = 0; i < max; i++) {
            if (this.buf[this.pos + i] != other.buf[other.pos + i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns a hashcode for this DerInputBuffer.
     *
     * @return a hashcode for this DerInputBuffer.
     */
    public int hashCode() {
        int retval = 0;

        int len = available();
        int p = pos;

        for (int i = 0; i < len; i++) {
            retval += buf[p + i] * i;
        }
        return retval;
    }

    void truncate(int len) throws IOException {
        if (len > available()) {
            throw new IOException("insufficient data");
        }
        count = pos + len;
    }

    /**
     * Returns the integer which takes up the specified number of bytes in this
     * buffer as a BigInteger.
     *
     * @param len the number of bytes to use.
     * @param makePositive whether to always return a positive value,
     * irrespective of actual encoding
     * @return the integer as a BigInteger.
     */
    BigInteger getBigInteger(int len, boolean makePositive) throws IOException {
        if (len > available()) {
            throw new IOException("short read of integer");
        }

        if (len == 0) {
            throw new IOException("Invalid encoding: zero length Int value");
        }

        byte[] bytes = new byte[len];

        System.arraycopy(buf, pos, bytes, 0, len);
        skip(len);

        // BER allows leading 0s but DER does not
        if (!allowBER && (len >= 2 && (bytes[0] == 0) && (bytes[1] >= 0))) {
            throw new IOException("Invalid encoding: redundant leading 0s");
        }

        if (makePositive) {
            return new BigInteger(1, bytes);
        } else {
            return new BigInteger(bytes);
        }
    }

    /**
     * Returns the integer which takes up the specified number of bytes in this
     * buffer.
     *
     * @throws IOException if the result is not within the valid range for
     * integer, i.e. between Integer.MIN_VALUE and Integer.MAX_VALUE.
     * @param len the number of bytes to use.
     * @return the integer.
     */
    public int getInteger(int len) throws IOException {

        BigInteger result = getBigInteger(len, false);
        if (result.compareTo(BigInteger.valueOf(Integer.MIN_VALUE)) < 0) {
            throw new IOException("Integer below minimum valid value");
        }
        if (result.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) > 0) {
            throw new IOException("Integer exceeds maximum valid value");
        }
        return result.intValue();
    }

    /**
     * Returns the bit string which takes up the specified number of bytes in
     * this buffer.
     */
    public byte[] getBitString(int len) throws IOException {
        if (len > available()) {
            throw new IOException("short read of bit string");
        }

        if (len == 0) {
            throw new IOException("Invalid encoding: zero length bit string");
        }

        int numOfPadBits = buf[pos];
        if ((numOfPadBits < 0) || (numOfPadBits > 7)) {
            throw new IOException("Invalid number of padding bits");
        }
        // minus the first byte which indicates the number of padding bits
        byte[] retval = new byte[len - 1];
        System.arraycopy(buf, pos + 1, retval, 0, len - 1);
        if (numOfPadBits != 0) {
            // get rid of the padding bits
            retval[len - 2] &= (0xff << numOfPadBits);
        }
        skip(len);
        return retval;
    }
}
