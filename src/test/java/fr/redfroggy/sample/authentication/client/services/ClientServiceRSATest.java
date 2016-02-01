package fr.redfroggy.sample.authentication.client.services;

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

import java.io.*;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

@RunWith(MockitoJUnitRunner.class)
public class ClientServiceRSATest {

    @Spy
    protected CipherService cipher = new CipherService(Algorithm.RSA, new byte[0]);

    @Mock
    protected Socket socket;

    @Mock
    protected OutputStream outputStream;

    @Mock
    protected InputStream inputStream;

    @Mock
    protected BufferedReader messageInput;

    @InjectMocks
    protected ClientService service = new ClientService();

    @Before
    public void init() throws Exception {
        Mockito.when(socket.getOutputStream()).thenReturn(outputStream);
        Mockito.when(socket.getInputStream()).thenReturn(inputStream);

        ReflectionTestUtils.setField(cipher, "keyPair", getKeyPair());
    }

    protected KeyPair getKeyPair() throws Exception {
        return new KeyPair(getPublicKey("public.key"), getPrivateKey("private.key"));
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

        byte[] serverKey = getPublicKey("server-public.key").getEncoded();

        /**
         * Server responses
         */
        Mockito.when(inputStream.read(new byte[64]))
                // Get server public key
                .thenAnswer(inputStreamAnswer(Arrays.copyOfRange(serverKey, 0, 64)))
                .thenAnswer(inputStreamAnswer(Arrays.copyOfRange(serverKey, 64, 128)))
                .thenAnswer(inputStreamAnswer(Arrays.copyOfRange(serverKey, 128, 192)))
                .thenAnswer(inputStreamAnswer(Arrays.copyOfRange(serverKey, 192, 256)))
                .thenAnswer(inputStreamAnswer(Arrays.copyOfRange(serverKey, 256, 294)))
                // Acknowledge
                .thenAnswer(inputStreamAnswer(BytesUtils.hexToBytes("30A98817BF")));

        /**
         * User message
         */
        Mockito.when(messageInput.readLine())
                // Get first message
                .thenReturn("Secret message to encode")
                        // Get end of transmission
                .thenReturn(null);

        service.run();

        Mockito.verify(outputStream).write(BytesUtils.hexToBytes("14 30 82 01 22 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00 03 82 01 0F 00 30 82 01 0A 02 82 01 01 00 AB 2A 0A 77 DC 13 4C C9 23 C9 D0 24 4F 73 97 1D 89 A7 95 69 A5 D2 64 FC DA 41 22 51 BA 3E 7A A3 25 BB C0 61 6F 96 BE 61 EA 9E 49 77 E4 92 62 48 83 C4 AE F7 F4 35 AB AA FC B2 6B 76 E2 45 21 8C DB 06 C7 7F A3 DE AE A4 AC D8 CC 93 E9 A0 40 EE 78 32 99 40 C6 10 A2 04 00 E1 82 18 70 E0 38 D0 4D 11 B9 36 94 8D 31 18 56 99 65 89 C5 95 00 4A 5E 65 4D 73 1B D5 DF 79 3A 3D 76 03 30 A5 CF E4 27 79 01 0E 65 F6 A1 A3 AE 57 58 A5 4C EC AA 87 5C E6 D9 D4 E0 DA 85 82 A7 8F 28 19 F9 CC 5D 12 DA 14 6C 0E 22 13 5F 20 F4 9E 4C D2 6D 20 88 1A 14 FF 16 E5 3A D1 08 4C EF 56 26 09 68 20 84 2F E3 7C 1B 50 F1 F5 75 3F DE 43 37 B4 CF 28 E1 66 5B 84 04 16 C1 57 35 5C 58 E2 A8 0D 43 D5 1A 17 08 0F 19 05 8A C0 C8 C5 82 5E E6 21 65 25 0D CC E9 FF 16 37 2F 47 AC A2 F1 E8 10 D4 38 66 A0 93 02 03 01 00 01"), 0, 295);
        Mockito.verify(outputStream).write(Mockito.any(byte[].class), Mockito.eq(0), Mockito.eq(257));

        Mockito.verify(socket, Mockito.times(1)).close();
    }
}
