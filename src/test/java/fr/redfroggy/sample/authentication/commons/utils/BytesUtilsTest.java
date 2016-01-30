package fr.redfroggy.sample.authentication.commons.utils;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class BytesUtilsTest {

    @Test
    public void bytesToHex_Byte() {
        String res = BytesUtils.bytesToHex((byte) 0x10);
        Assert.assertEquals("10", res);
    }

    @Test
    public void bytesToHex_Bytes() {
        String res = BytesUtils.bytesToHex(new byte[] { (byte) 0x10, (byte) 0x11, (byte) 0x12 });
        Assert.assertEquals("10 11 12", res);
    }

    @Test
    public void bytesToHex_BytesWithCustomSeparator() {
        String res = BytesUtils.bytesToHex(new byte[] { (byte) 0x10, (byte) 0x11, (byte) 0x12 }, '-');
        Assert.assertEquals("10-11-12", res);
    }

    @Test
    public void bytesToHex_BytesWithCustomSeparatorAndPaging() {
        String res = BytesUtils.bytesToHex(new byte[] { (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13 }, '-', 2);
        Assert.assertEquals("10-11\n12-13", res);
    }

    @Test
    public void bytesToHex_CRC32() {
        byte[] expected = new byte[] { (byte) 0x36, (byte) 0x8f,  (byte) 0x0c, (byte) 0x6f };
        byte[] crc = BytesUtils.crc32(new byte[] { (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13 });
        Assert.assertArrayEquals(expected, crc);
    }

    @Test
    public void bytesToHex_hexToBytes() {
        byte[] expected = new byte[] { (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x4d };
        byte[] res = BytesUtils.hexToBytes("10-11 12:4D");
        Assert.assertArrayEquals(expected, res);
    }
}
