package fr.redfroggy.sample.tpa.server.services;

import fr.redfroggy.sample.tpa.commons.security.Algorithm;
import fr.redfroggy.sample.tpa.commons.security.CipherService;
import fr.redfroggy.sample.tpa.commons.utils.BytesUtils;
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

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.ServerSocket;
import java.net.Socket;

@RunWith(MockitoJUnitRunner.class)
public class ServerServiceTest {

    protected static final byte[] KEY_AES = BytesUtils.hexToBytes("7788554411224455DD66E8F6F2B4A54E");

    @Spy
    protected CipherService cipher = new CipherService(Algorithm.AES, KEY_AES);

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
    public void run_Nominal() throws Exception {

        /**
         * Client command
         */
        Mockito.when(inputStream.read(new byte[64]))
                // Get server challenge #1
                .thenAnswer(inputStreamAnswer(BytesUtils.hexToBytes("13")))
                // Check client challenge
                .thenAnswer(inputStreamAnswer(BytesUtils.hexToBytes("1214DF8CC9F9A0C5E32621F9322CAE72803E9F1B38B9E2CDC3810AD1B49C0291C5")))
                // Get server challenge #2
                .thenAnswer(inputStreamAnswer(BytesUtils.hexToBytes("11778899AABBCCD00112233445566DEEFF")))
                // Message
                .thenAnswer(inputStreamAnswer(BytesUtils.hexToBytes("204EDA4321842C82F643DB9CC26606207170A979D5E340EE5AD0B44F88B21AC257")))
                // Stop
                .thenAnswer(inputStreamAnswer(BytesUtils.hexToBytes("FF")));

        /**
         * Server socket
         */
        Mockito.when(serverSocket.accept()).thenReturn(socket);
        Mockito.when(socket.isConnected()).thenReturn(true).thenReturn(false);
        Mockito.when(socket.getInetAddress()).thenReturn(Inet4Address.getLocalHost());

        /**
         * Cipher Randomize
         */
        Mockito.when(cipher.random())
                // Get client challenge #1
                .thenReturn(BytesUtils.hexToBytes("AABBCCDDEEFF00112233445566778899"))
                        // Get client challenge #2
                .thenReturn(BytesUtils.hexToBytes("885684629592D2E4C5D88462CD84EFAB"));

        service.run();

        Mockito.verify(serverSocket, Mockito.times(1)).close();
    }
}
