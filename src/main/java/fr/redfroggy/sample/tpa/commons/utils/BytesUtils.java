package fr.redfroggy.sample.tpa.commons.utils;

import com.google.common.primitives.Bytes;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.ArrayUtils;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Tools used to manipulate bytes and bytes array
 *
 * @author Florent PERINEL
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public abstract class BytesUtils {

    /**
     * Default delimiter for hexadecimal values
     */
    public static final char DEFAULT_HEXA_DELIMITER = ':';

    /**
     * Format bytes array to hexadecimal representation
     *
     * @param byteToFormat Byte to format
     * @return hexadecimal representation
     */
    public static String bytesToHex(byte byteToFormat) {
        return bytesToHex(new byte[]{byteToFormat});
    }

    /**
     * Format bytes array to hexadecimal representation
     *
     * @param bytes Bytes array to format
     * @return hexadecimal representation
     */
    public static String bytesToHex(byte[] bytes) {
        return bytesToHex(bytes, DEFAULT_HEXA_DELIMITER, bytes.length);
    }

    /**
     * Convert byte array to string
     *
     * @param bytes byte array
     * @return string
     */
    public static String bytesToHexNoSeparator(byte[] bytes) {
        StringBuilder hexa = new StringBuilder();

        for (byte b : bytes) {
            hexa.append(String.format("%02X", b));
        }

        return hexa.toString();
    }

    /**
     * Format bytes array to hexadecimal representation
     *
     * @param bytes     Bytes array to format
     * @param separator Char used to separate hex values
     * @return hexadecimal representation
     */
    public static String bytesToHex(byte[] bytes, char separator) {
        return bytesToHex(bytes, separator, bytes.length);
    }

    /**
     * Format bytes array to hexadecimal representation
     *
     * @param bytes      Bytes array to format
     * @param separator  Char used to separate hex values
     * @param bytePerRow Number of byte per row
     * @return hexadecimal representation
     */
    public static String bytesToHex(byte[] bytes, char separator, int bytePerRow) {

        int count = 0;
        StringBuilder hexa = new StringBuilder();

        for (int i = 0; i < bytes.length; i++) {
            if (bytePerRow > 0 && count == bytePerRow) {
                hexa.append('\n');
                count = 0;
            } else if (i > 0) {
                hexa.append(separator);
            }

            hexa.append(String.format("%02X", bytes[i]));
            count++;
        }

        return hexa.toString();
    }

    /**
     * Format hexadecimal representation to bytes array
     *
     * @param hexadecimal hexadecimal representation
     * @param separator   Char used to separate hex values
     * @return bytes array
     */
    public static byte[] hexToBytes(String hexadecimal, char separator) {
        return hexToBytes(hexadecimal.replace(Character.toString(separator), "").replace("\n", ""));
    }

    /**
     * Format hexadecimal representation to bytes array
     *
     * @param hexadecimal hexadecimal representation
     * @return bytes array
     */
    public static byte[] hexToBytes(String hexadecimal) {
        String cleanedHexa = hexadecimal.replace(Character.toString(DEFAULT_HEXA_DELIMITER), "").replace("\n", "");
        int len = cleanedHexa.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(cleanedHexa.charAt(i), 16) << 4)
                    + Character.digit(cleanedHexa.charAt(i + 1), 16));
        }

        return data;
    }

    /**
     * Rotate 1 byte left
     *
     * @param data Data to rotate
     * @return Rotated data
     */
    public static byte[] rotateLeft(byte[] data) {
        return Bytes.concat(Arrays.copyOfRange(data, 1, data.length), new byte[]{data[0]});
    }

    /**
     * Rotate 1 byte riht
     *
     * @param data Data to rotate
     * @return Rotated data
     */
    public static byte[] rotateRight(byte[] data) {
        return Bytes.concat(new byte[]{data[data.length - 1]}, Arrays.copyOfRange(data, 0, data.length - 1));
    }


    /**
     * Reverse byte array
     *
     * @param data Data to reverse
     * @return Reversed data
     */
    public static byte[] reverseBytes(byte[] data) {
        byte[] reversed = ArrayUtils.clone(data);
        ArrayUtils.reverse(reversed);
        return reversed;
    }

    /**
     * Inverse byte value
     *
     * @param data Byte to inverse
     * @return Inversed byte
     */
    public static byte[] inverseBits(byte[] data) {
        byte[] result = new byte[data.length];

        for (int idx = 0; idx < data.length; idx++) {
            result[idx] = (byte) (data[idx] ^ 0xff);
        }

        return result;
    }

    /**
     * Build a fixed size byte array from a int value
     *
     * @param value     Value to convert to byte array
     * @param arraySize Array size required (max 4 / int)
     * @return Byte array
     */
    public static byte[] toFixedByteArray(int value, int arraySize) {
        byte[] array = ByteBuffer.allocate(4).putInt(value).array();
        return Arrays.copyOfRange(array, array.length - arraySize, array.length);
    }

    /**
     * Build a fixed size byte array from a byte array
     *
     * @param array     Array to reduce
     * @param arraySize Array size required (max 4 / int)
     * @return Byte array
     */
    public static byte[] toFixedByteArray(byte[] array, int arraySize) {
        if (array.length == arraySize) {
            return array;
        }

        return Arrays.copyOfRange(array, array.length - arraySize, arraySize + 1);
    }

    /**
     * Compute a CRC 32 for ISO 14443a cards
     *
     * @param data Data to check
     * @return 4 bytes array crc 32
     */
    public static byte[] crc32(byte[] data) {
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(data, 0, data.length);
        long l = crc.getValue();

        byte[] ret = new byte[4];
        for (int i = 0; i < 4; i++) {
            ret[i] = (byte) (l & 0x00000000000000ff);
            ret[i] = (byte) ~ret[i];
            l >>>= 8;
        }

        return ret;
    }

    /**
     * Compute a CRC 16 for ISO 14443a cards
     *
     * @param data Data to check
     * @return 2 bytes array crc 16
     */
    public static byte[] crc16(byte[] data) {
        int i = 0x6363;

        for (byte b : data) {
            int k = b & 0xFF;
            int tmp = (i ^ k) & 0xFF;
            k = (tmp ^ tmp << 4) & 0xFF;
            i = i >> 8 ^ k << 8 ^ k << 3 ^ k >> 4;
        }

        byte[] bb = new byte[2];
        bb[0] = (byte) (i & 0xff);
        bb[1] = (byte) ((i >> 8) & 0xff);
        return bb;
    }

    /**
     * Compute a CRC 8 for ISO 14443a cards
     *
     * @param data Data to check
     * @return 2 bytes array crc 16
     */
    public static byte crc8(byte[] data) {
        int poly = 0x1d;
        byte crc = (byte) 0xc7;

        for (byte b : data) {
            crc ^= b;
            for (int i = 7; i >= 0; i--) {
                int bitOut = crc & 0x80;
                crc <<= 1;
                if (bitOut == 0x80) {
                    crc ^= poly;
                }
            }
        }

        return crc;
    }

    /**
     * Apply a XOR function on two bytes array an return the result
     *
     * @param data1 Data 1
     * @param data2 Data 2
     * @return Data after XOR
     */
    public static byte[] xor(byte[] data1, byte[] data2) {
        byte[] result = new byte[data1.length < data2.length ? data2.length : data1.length];
        for (int i = 0; i < result.length; i++) {
            result[i] = ((byte) (data1[i] ^ data2[i]));
        }

        return result;
    }


    /**
     * Pad byte array to n*multiple size
     *
     * @param data     Data to pad
     * @param multiple Multiple bloc size
     * @return Data padded
     */
    public static byte[] pad(byte[] data, int multiple) {
        return pad(data, multiple, false);
    }

    /**
     * Pad byte array to n*multiple size
     *
     * @param data     Data to pad
     * @param multiple Multiple bloc size
     * @param iso      Use ISO/IEC 9797 padding
     * @return Data padded
     */
    public static byte[] pad(byte[] data, int multiple, boolean iso) {
        if (data.length % multiple == 0) {
            return data;
        }

        int padding;
        if (data.length < multiple) {
            padding = multiple - data.length;
        } else {
            padding = ((data.length / multiple + 1) * multiple) - data.length;
        }

        byte[] paddingValue = new byte[padding];
        if (padding > 0 && iso) {
            paddingValue[0] = (byte) 0x80;
        }

        return Bytes.concat(data, paddingValue);
    }

    /**
     * Trim the padding
     *
     * @param data Data to unpad
     * @return Unpaded data
     */
    public static byte[] unpad(byte[] data) {
        return BytesUtils.unpad(data, false);
    }

    /**
     * Trim the padding
     *
     * @param data    Data to unpad
     * @param iso9797 True if ISO9797 must be respected (0x80)
     * @return Unpaded data
     */
    public static byte[] unpad(byte[] data, boolean iso9797) {
        for (int s = data.length - 1; s >= 0; s--) {
            if (data[s] != (byte) 0x00) {
                int offset = data[s] == (byte) 0x80 && iso9797 ? 0 : 1;
                return Arrays.copyOfRange(data, 0, s + offset);
            }
        }

        return data;
    }

    /**
     * Shift bit left
     *
     * @param data Data to shift
     * @return Shifted data
     */
    public static byte[] shiftLeft(byte[] data) {

        StringBuilder sb = new StringBuilder();

        for (byte b : data) {
            String s = Integer.toBinaryString(0x100 + b);
            sb.append(s.subSequence(s.length() - 8, s.length()));
        }

        String s = sb.toString().substring(1) + "0";

        byte[] a = new byte[s.length() / 8];

        for (int index = 0, i = 0; i < s.length(); index++, i += 8) {
            a[index] = (byte) Integer.parseInt(s.substring(i, i + 8), 2);
        }

        return a;
    }

    /**
     * Cut byte array in smaller byte arrays
     *
     * @param data      All byte array
     * @param chunkSize Chunk size
     * @return byte arrays
     */
    public static List<byte[]> split(byte[] data, int chunkSize) {
        List<byte[]> ret = new ArrayList<>();

        int nbChunk = (int) Math.ceil(data.length / (double) chunkSize);
        int start = 0;

        for (int i = 0; i < nbChunk; i++) {
            ret.add(Arrays.copyOfRange(data, start, start + Math.min(chunkSize, data.length - start)));
            start += chunkSize;
        }

        return ret;
    }

    /**
     * Convert a byte array to int value
     *
     * @param data Byte array
     * @return Integer value
     */
    public static int bytesArrayToInt(byte[] data) {
        return new BigInteger(BytesUtils.reverseBytes(data)).intValue();
    }

    /*public static byte[] addEndOfLine(byte[] data) {
        byte[] dataEOL = new byte[data.length + 1];
        System.arraycopy(data, 0, dataEOL, 0, data.length);
        dataEOL[dataEOL.length - 1] = (byte) '\n';
        return dataEOL;
    }*/

}
