package fr.redfroggy.sample.tpa.server.configuration;

import fr.redfroggy.sample.tpa.commons.security.Algorithm;
import fr.redfroggy.sample.tpa.commons.security.CipherService;
import fr.redfroggy.sample.tpa.commons.utils.BytesUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.net.ServerSocket;

/**
 * Server configuration
 */
@Configuration
public class ServerConfiguration {

    @Autowired
    protected SocketSettings settings;

    @Autowired
    protected KeySettings keySettings;

    /**
     * Construct server socket
     *
     * @return Server socket
     * @throws IOException If an error occurred during socket construction
     */
    @Bean
    public ServerSocket getServerSocket() throws IOException {
        return new ServerSocket(settings.getPort());
    }

    /**
     * Construct server cipher
     *
     * @return Server cipher
     */
    @Bean
    public CipherService getServerCipher() {
        Algorithm algorithm = Algorithm.valueOf(keySettings.getAlgorithm());
        byte[] key = BytesUtils.hexToBytes(keySettings.getKey());
        return new CipherService(algorithm, key);
    }
}
