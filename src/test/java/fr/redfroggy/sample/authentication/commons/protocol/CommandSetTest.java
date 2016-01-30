package fr.redfroggy.sample.authentication.commons.protocol;

import fr.redfroggy.sample.authentication.commons.utils.BytesUtils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class CommandSetTest {

    @Test
    public void authenticateClient() {
        byte[] expected = BytesUtils.hexToBytes("12:00:11:22:33:44:55:66:77");
        byte[] authC = BytesUtils.hexToBytes("00:11:22:33:44:55:66:77");
        byte[] cmd = CommandSet.authenticateClient(authC);
        Assert.assertArrayEquals(expected, cmd);
    }

    @Test
    public void authenticateServer() {
        byte[] expected = BytesUtils.hexToBytes("11:00:11:22:33:44:55:66:77");
        byte[] authC = BytesUtils.hexToBytes("00:11:22:33:44:55:66:77");
        byte[] cmd = CommandSet.authenticateServer(authC);
        Assert.assertArrayEquals(expected, cmd);
    }

    @Test
    public void getChallenge() {
        byte[] expected = BytesUtils.hexToBytes("13");
        byte[] cmd = CommandSet.getChallenge();
        Assert.assertArrayEquals(expected, cmd);
    }

    @Test
    public void receive() {
        byte[] expected = BytesUtils.hexToBytes("30:56:54");
        byte[] crc = BytesUtils.hexToBytes("56:54");
        byte[] cmd = CommandSet.receive(crc);
        Assert.assertArrayEquals(expected, cmd);
    }

    @Test
    public void sendMessage() {
        byte[] expected = BytesUtils.hexToBytes("20:56:54:56:54:56:54:56:54:56:54");
        byte[] message = BytesUtils.hexToBytes("56:54:56:54:56:54:56:54:56:54");
        byte[] cmd = CommandSet.sendMessage(message);
        Assert.assertArrayEquals(expected, cmd);
    }

    @Test
    public void stop() {
        byte[] expected = BytesUtils.hexToBytes("FF");
        byte[] cmd = CommandSet.stop();
        Assert.assertArrayEquals(expected, cmd);
    }

    @Test
    public void success() {
        byte[] expected = BytesUtils.hexToBytes("E0");
        byte[] cmd = CommandSet.success();
        Assert.assertArrayEquals(expected, cmd);
    }

    @Test
    public void error() {
        String error = "Mocked error";
        byte[] expected = BytesUtils.hexToBytes("F0:" + BytesUtils.bytesToHex(error.getBytes()));
        byte[] cmd = CommandSet.error(error);
        Assert.assertArrayEquals(expected, cmd);
    }
}
