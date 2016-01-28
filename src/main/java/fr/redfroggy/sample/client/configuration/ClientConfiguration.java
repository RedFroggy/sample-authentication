package fr.redfroggy.sample.client.configuration;

import fr.redfroggy.sample.commons.security.Algorithm;
import fr.redfroggy.sample.commons.security.CipherService;
import fr.redfroggy.sample.commons.utils.BytesUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.net.Socket;

@Configuration
public class ClientConfiguration {

    public static final String SOCKET = "clientSocket";

    public static final String CIPHER = "clientCipher";

    @Autowired
    protected SocketSettings settings;

    @Autowired
    protected KeySettings keySettings;

    @Bean(name = ClientConfiguration.SOCKET)
    public Socket getClientSocket() throws IOException {
        return new Socket(settings.getHost(), settings.getPort());
    }

    @Bean(name = ClientConfiguration.CIPHER)
    public CipherService getClientCipher() {
        Algorithm algorithm = Algorithm.valueOf(keySettings.getAlgorithm());
        byte[] key = BytesUtils.hexToBytes(keySettings.getKey());
        return new CipherService(algorithm, key);
    }
}
