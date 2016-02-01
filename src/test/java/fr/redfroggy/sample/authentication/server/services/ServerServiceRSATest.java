package fr.redfroggy.sample.authentication.server.services;

import fr.redfroggy.sample.authentication.commons.security.Algorithm;
import fr.redfroggy.sample.authentication.commons.security.CipherService;
import fr.redfroggy.sample.authentication.commons.utils.BytesUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

@RunWith(MockitoJUnitRunner.class)
public class ServerServiceRSATest {

    @Spy
    protected CipherService cipher = new CipherService(Algorithm.RSA, new byte[0]);

    @Mock
    protected Socket socket;

    @Mock
    protected ServerSocket serverSocket;

    @Mock
    protected OutputStream outputStream;

    @Mock
    protected InputStream inputStream;

    @InjectMocks
    protected ServerService service = new ServerService();

    @Before
    public void init() throws Exception {
        Mockito.when(socket.getOutputStream()).thenReturn(outputStream);
        Mockito.when(socket.getInputStream()).thenReturn(inputStream);

        ReflectionTestUtils.setField(cipher, "keyPair", getKeyPair());
    }

    protected KeyPair getKeyPair() throws Exception {
        return new KeyPair(getPublicKey("server-public.key"), getPrivateKey("server-private.key"));
    }

    protected PublicKey getPublicKey(String fileName) throws Exception {
        File f = new File(getClass().getResource("/" + fileName).getFile());
        FileInputStream filePublicKey = new FileInputStream(f);
        byte[] encodedPublicKey = new byte[(int) f.length()];
        filePublicKey.read(encodedPublicKey);
        filePublicKey.close();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
        return keyFactory.generatePublic(publicKeySpec);
    }

    protected PrivateKey getPrivateKey(String fileName) throws Exception {
        File f = new File(getClass().getResource("/" + fileName).getFile());
        FileInputStream filePrivateKey = new FileInputStream(f);
        byte[] encodedPrivateKey = new byte[(int) f.length()];
        filePrivateKey.read(encodedPrivateKey);
        filePrivateKey.close();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        return keyFactory.generatePrivate(privateKeySpec);
    }

    protected Answer<Integer> inputStreamAnswer(final byte[] data) {
        return new Answer<Integer>() {
            @Override
            public Integer answer(InvocationOnMock invocation) throws Throwable {
                Object[] args = invocation.getArguments();
                System.arraycopy(data, 0, args[0], 0, data.length);
                return data.length;
            }
        };
    }

    @Test
    public void run_Nominal_RSA() throws Exception {

        byte[] clientKey = getPublicKey("public.key").getEncoded();
        byte[] message = BytesUtils.hexToBytes("201301CAF7123E53289DDFE26D3E1ECCD53194DCD25060A81D972CA05945725843375A5A2FBDC208BEA643B5880029A922D67A94E05D04C803C377FB07A105CF27D9A830FEEB0A6CE2C41CC7C39037507090B727911CD7C1849E888E0A47D2E421501F603E24F21F1B584C4ACD47763176413F4522116262D20CCB264B226B4EC8600327EC517BE40994E466CAC7E1CA5B1BEC84E9153D3C1E78E54A3720208AF5BFF7C36A58FFC3595DF23C3B5D4531AD19144DCF71A4AB975DD8AE1E29EF77971091C1D806774704DE8EAA0ABD3AF7E03441CEC6C8936D24ED4FD0E9180552D5B7CF923506905A655AC8961B127160890CF987140B16AE127C8ACC02E76FBF67");

        /**
         * Server responses
         */
        Mockito.when(inputStream.read(new byte[64]))
                // Get client public key
                .thenAnswer(inputStreamAnswer(Arrays.copyOfRange(clientKey, 0, 64)))
                .thenAnswer(inputStreamAnswer(Arrays.copyOfRange(clientKey, 64, 128)))
                .thenAnswer(inputStreamAnswer(Arrays.copyOfRange(clientKey, 128, 192)))
                .thenAnswer(inputStreamAnswer(Arrays.copyOfRange(clientKey, 192, 256)))
                .thenAnswer(inputStreamAnswer(Arrays.copyOfRange(clientKey, 256, 294)))
                // Message
                .thenAnswer(inputStreamAnswer(Arrays.copyOfRange(message, 0, 64)))
                .thenAnswer(inputStreamAnswer(Arrays.copyOfRange(message, 64, 128)))
                .thenAnswer(inputStreamAnswer(Arrays.copyOfRange(message, 128, 192)))
                .thenAnswer(inputStreamAnswer(Arrays.copyOfRange(message, 192, 256)))
                .thenAnswer(inputStreamAnswer(Arrays.copyOfRange(message, 256, 257)))
                // Stop
                .thenAnswer(inputStreamAnswer(BytesUtils.hexToBytes("FF")));

        /**
         * Server socket
         */
        Mockito.when(serverSocket.accept()).thenReturn(socket);
        Mockito.when(socket.isConnected()).thenReturn(true).thenReturn(false);
        Mockito.when(socket.getInetAddress()).thenReturn(Inet4Address.getLocalHost());

        service.run();

        Mockito.verify(outputStream).write(BytesUtils.hexToBytes("F0 55 6E 6B 6E 6F 77 6E 20 69 6E 73 74 72 75 63 74 69 6F 6E"), 0, 20);
        Mockito.verify(outputStream).write(BytesUtils.hexToBytes("30 A9 88 17 BF"), 0, 5);

        Mockito.verify(serverSocket, Mockito.times(1)).close();
    }
}
