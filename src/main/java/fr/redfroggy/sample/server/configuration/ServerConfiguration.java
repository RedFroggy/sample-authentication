package fr.redfroggy.sample.server.configuration;

import fr.redfroggy.sample.commons.security.Algorithm;
import fr.redfroggy.sample.commons.security.CipherService;
import fr.redfroggy.sample.commons.utils.BytesUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.net.ServerSocket;

@Configuration
public class ServerConfiguration {

    public static final String SOCKET = "serverSocket";

    public static final String CIPHER = "serverCipher";

    @Autowired
    protected SocketSettings settings;

    @Autowired
    protected KeySettings keySettings;

    @Bean(name = ServerConfiguration.SOCKET)
    public ServerSocket getServerSocket() throws IOException {
        return new ServerSocket(settings.getPort());
    }

    @Bean(name = ServerConfiguration.CIPHER)
    public CipherService getServerCipher() {
        Algorithm algorithm = Algorithm.valueOf(keySettings.getAlgorithm());
        byte[] key = BytesUtils.hexToBytes(keySettings.getKey());
        return new CipherService(algorithm, key);
    }
}
