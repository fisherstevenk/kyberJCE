/*
 * Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
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

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * Output stream marshaling DER-encoded data. This is eventually provided in the
 * form of a byte array; there is no advance limit on the size of that byte
 * array.
 *
 * <P>
 * At this time, this class supports only a subset of the types of DER data
 * encodings which are defined. That subset is sufficient for generating most
 * X.509 certificates.
 *
 *
 * @author David Brownell
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 */
public class DerOutputStream
        extends ByteArrayOutputStream implements DerEncoder {

    /**
     * Construct an DER output stream.
     *
     * @param size how large a buffer to preallocate.
     */
    public DerOutputStream(int size) {
        super(size);
    }

    /**
     * Construct an DER output stream.
     */
    public DerOutputStream() {
    }

    /**
     * Writes tagged, pre-marshaled data. This calcuates and encodes the length,
     * so that the output data is the standard triple of { tag, length, data }
     * used by all DER values.
     *
     * @param tag the DER value tag for the data, such as
     * <em>DerValue.tag_Sequence</em>
     * @param buf buffered data, which must be DER-encoded
     */
    public void write(byte tag, byte[] buf) throws IOException {
        write(tag);
        putLength(buf.length);
        write(buf, 0, buf.length);
    }

    /**
     * Writes tagged data using buffer-to-buffer copy. As above, this writes a
     * standard DER record. This is often used when efficiently encapsulating
     * values in sequences.
     *
     * @param tag the DER value tag for the data, such as
     * <em>DerValue.tag_Sequence</em>
     * @param out buffered data
     */
    public void write(byte tag, DerOutputStream out) throws IOException {
        write(tag);
        putLength(out.count);
        write(out.buf, 0, out.count);
    }

    /**
     * Marshals pre-encoded DER value onto the output stream.
     */
    public void putDerValue(DerValue val) throws IOException {
        val.encode(this);
    }

    /**
     * Marshals a DER integer on the output stream.
     *
     * @param i the integer in the form of a BigInteger.
     */
    public void putInteger(BigInteger i) throws IOException {
        write(DerValue.tag_Integer);
        byte[] buf = i.toByteArray(); // least number  of bytes
        putLength(buf.length);
        write(buf, 0, buf.length);
    }

    /**
     * Marshals a DER integer on the output stream.
     *
     * @param i the integer in the form of an Integer.
     */
    public void putInteger(Integer i) throws IOException {
        putInteger(i.intValue());
    }

    /**
     * Marshals a DER integer on the output stream.
     *
     * @param i the integer.
     */
    public void putInteger(int i) throws IOException {
        write(DerValue.tag_Integer);
        putIntegerContents(i);
    }

    private void putIntegerContents(int i) throws IOException {

        byte[] bytes = new byte[4];
        int start = 0;

        // Obtain the four bytes of the int
        bytes[3] = (byte) (i & 0xff);
        bytes[2] = (byte) ((i & 0xff00) >>> 8);
        bytes[1] = (byte) ((i & 0xff0000) >>> 16);
        bytes[0] = (byte) ((i & 0xff000000) >>> 24);

        // Reduce them to the least number of bytes needed to
        // represent this int
        if (bytes[0] == (byte) 0xff) {

            // Eliminate redundant 0xff
            for (int j = 0; j < 3; j++) {
                if ((bytes[j] == (byte) 0xff)
                        && ((bytes[j + 1] & 0x80) == 0x80)) {
                    start++;
                } else {
                    break;
                }
            }
        } else if (bytes[0] == 0x00) {

            // Eliminate redundant 0x00
            for (int j = 0; j < 3; j++) {
                if ((bytes[j] == 0x00)
                        && ((bytes[j + 1] & 0x80) == 0)) {
                    start++;
                } else {
                    break;
                }
            }
        }

        putLength(4 - start);
        for (int k = start; k < 4; k++) {
            write(bytes[k]);
        }
    }

    /**
     * Marshals a DER bit string on the output stream. The bit string must be
     * byte-aligned.
     *
     * @param bits the bit string, MSB first
     */
    public void putBitString(byte[] bits) throws IOException {
        write(DerValue.tag_BitString);
        putLength(bits.length + 1);
        write(0);               // all of last octet is used
        write(bits);
    }

    /**
     * DER-encodes an ASN.1 OCTET STRING value on the output stream.
     *
     * @param octets the octet string
     */
    public void putOctetString(byte[] octets) throws IOException {
        write(DerValue.tag_OctetString, octets);
    }

    /**
     * Marshals an object identifier (OID) on the output stream. Corresponds to
     * the ASN.1 "OBJECT IDENTIFIER" construct.
     */
    public void putOID(ObjectIdentifier oid) throws IOException {
        oid.encode(this);
    }

    /**
     * Put the encoding of the length in the stream.
     *
     * @param len the length of the attribute.
     * @exception IOException on writing errors.
     */
    public void putLength(int len) throws IOException {
        if (len < 128) {
            write((byte) len);

        } else if (len < (1 << 8)) {
            write((byte) 0x081);
            write((byte) len);

        } else if (len < (1 << 16)) {
            write((byte) 0x082);
            write((byte) (len >> 8));
            write((byte) len);

        } else if (len < (1 << 24)) {
            write((byte) 0x083);
            write((byte) (len >> 16));
            write((byte) (len >> 8));
            write((byte) len);

        } else {
            write((byte) 0x084);
            write((byte) (len >> 24));
            write((byte) (len >> 16));
            write((byte) (len >> 8));
            write((byte) len);
        }
    }

    /**
     * Write the current contents of this <code>DerOutputStream</code> to an
     * <code>OutputStream</code>.
     *
     * @exception IOException on output error.
     */
    public void derEncode(OutputStream out) throws IOException {
        out.write(toByteArray());
    }
}
