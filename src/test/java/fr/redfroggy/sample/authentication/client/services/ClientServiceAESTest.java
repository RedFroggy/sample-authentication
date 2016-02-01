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

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

@RunWith(MockitoJUnitRunner.class)
public class ClientServiceAESTest {

    protected static final byte[] KEY_AES = BytesUtils.hexToBytes("7788554411224455DD66E8F6F2B4A54E");

    @Spy
    protected CipherService cipher = new CipherService(Algorithm.AES, KEY_AES);

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
    public void run_Nominal_AES() throws Exception {

        /**
         * Server responses
         */
        Mockito.when(inputStream.read(new byte[64]))
                // Get server challenge #1
                .thenAnswer(inputStreamAnswer(BytesUtils.hexToBytes("AABBCCDDEEFF00112233445566778899")))
                // Check client challenge
                .thenAnswer(inputStreamAnswer(BytesUtils.hexToBytes("E0")))
                // Get server challenge #2
                .thenAnswer(inputStreamAnswer(BytesUtils.hexToBytes("904F58BA799240772D990FAB2F245E2923F8E15D7496CA5217527ECBAE3C3381")))
                // Acknowledge
                .thenAnswer(inputStreamAnswer(BytesUtils.hexToBytes("30A98817BF")));

        /**
         * Cipher Randomize
         */
        Mockito.when(cipher.random())
                // Get client challenge #1
                .thenReturn(BytesUtils.hexToBytes("00112233445566778899AABBCCDDEEFF"))
                // Get client challenge #2
                .thenReturn(BytesUtils.hexToBytes("778899AABBCCD00112233445566DEEFF"));

        /**
         * User message
         */
        Mockito.when(messageInput.readLine())
                // Get first message
                .thenReturn("Secret message to encode")
                // Get end of transmission
                .thenReturn(null);

        service.run();

        Mockito.verify(outputStream).write(BytesUtils.hexToBytes("13"), 0, 1);
        Mockito.verify(outputStream).write(BytesUtils.hexToBytes("12 14 DF 8C C9 F9 A0 C5 E3 26 21 F9 32 2C AE 72 80 3E 9F 1B 38 B9 E2 CD C3 81 0A D1 B4 9C 02 91 C5"), 0, 33);
        Mockito.verify(outputStream).write(BytesUtils.hexToBytes("11 77 88 99 AA BB CC D0 01 12 23 34 45 56 6D EE FF"), 0, 17);
        Mockito.verify(outputStream).write(BytesUtils.hexToBytes("20 4E DA 43 21 84 2C 82 F6 43 DB 9C C2 66 06 20 71 70 A9 79 D5 E3 40 EE 5A D0 B4 4F 88 B2 1A C2 57"), 0, 33);

        Mockito.verify(socket, Mockito.times(1)).close();
    }
}
