package fr.redfroggy.sample.tpa.commons.security;

import fr.redfroggy.sample.tpa.commons.utils.BytesUtils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class CipherServiceTest {

    protected static final byte[] KEY_AES = BytesUtils.hexToBytes("7788554411224455DD66E8F6F2B4A54E");
    protected static final byte[] KEY_DES = BytesUtils.hexToBytes("0011223344556677");
    protected static final byte[] KEY_TDES = BytesUtils.hexToBytes("7788554411224455DD66E8F6F2B4A54E");
    protected static final byte[] KEY_TKTDES = BytesUtils.hexToBytes("77885DD66E8F6F2B4A54E54411224455DD66E8F6F2B4A54E");

    protected CipherService service;

    @Test
    public void randomAES() {
        service = new CipherService(Algorithm.AES, KEY_AES);
        byte[] rnd = service.random();
        Assert.assertEquals(16, rnd.length);
    }

    @Test
    public void randomDES() {
        service = new CipherService(Algorithm.DES, KEY_DES);
        byte[] rnd = service.random();
        Assert.assertEquals(8, rnd.length);
    }

    @Test
    public void randomTDES() {
        service = new CipherService(Algorithm.TDES, KEY_TDES);
        byte[] rnd = service.random();
        Assert.assertEquals(8, rnd.length);
    }

    @Test
    public void randomTKTDES() {
        service = new CipherService(Algorithm.TKTDES, KEY_TKTDES);
        byte[] rnd = service.random();
        Assert.assertEquals(8, rnd.length);
    }

    @Test
    public void encodeDecodeAES() throws Exception {

        byte[] expected = "SECRET MESSAGE".getBytes();

        service = new CipherService(Algorithm.AES, KEY_AES);
        byte[] eKexpected = service.encode(expected);
        byte[] dKexpected = service.decode(eKexpected);

        Assert.assertArrayEquals(expected, dKexpected);
    }

    @Test
    public void encodeDecodeDES() throws Exception {

        byte[] expected = "SECRET MESSAGE".getBytes();

        service = new CipherService(Algorithm.DES, KEY_DES);
        byte[] eKexpected = service.encode(expected);
        byte[] dKexpected = service.decode(eKexpected);

        Assert.assertArrayEquals(expected, dKexpected);
    }

    @Test
    public void encodeDecodeTDES() throws Exception {

        byte[] expected = "SECRET MESSAGE".getBytes();

        service = new CipherService(Algorithm.TDES, KEY_TDES);
        byte[] eKexpected = service.encode(expected);
        byte[] dKexpected = service.decode(eKexpected);

        Assert.assertArrayEquals(expected, dKexpected);
    }

    @Test
    public void encodeDecodeTKTDES() throws Exception {

        byte[] expected = "SECRET MESSAGE".getBytes();

        service = new CipherService(Algorithm.TKTDES, KEY_TKTDES);
        byte[] eKexpected = service.encode(expected);
        byte[] dKexpected = service.decode(eKexpected);

        Assert.assertArrayEquals(expected, dKexpected);
    }
}
