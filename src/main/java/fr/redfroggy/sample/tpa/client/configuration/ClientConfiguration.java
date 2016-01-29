package fr.redfroggy.sample.tpa.client.configuration;

import fr.redfroggy.sample.tpa.commons.security.Algorithm;
import fr.redfroggy.sample.tpa.commons.security.CipherService;
import fr.redfroggy.sample.tpa.commons.utils.BytesUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;

/**
 * Client configuration
 */
@Configuration
public class ClientConfiguration {

    @Autowired
    protected SocketSettings settings;

    @Autowired
    protected KeySettings keySettings;

    /**
     * Construct client socket
     *
     * @return Client socket
     * @throws IOException If an error occurred during socket construction
     */
    @Bean
    public Socket getClientSocket() throws IOException {
        return new Socket(settings.getHost(), settings.getPort());
    }

    /**
     * Construct client cipher
     *
     * @return Client cipher
     */
    @Bean
    public CipherService getClientCipher() {
        Algorithm algorithm = Algorithm.valueOf(keySettings.getAlgorithm());
        byte[] key = BytesUtils.hexToBytes(keySettings.getKey());
        return new CipherService(algorithm, key);
    }

    /**
     * Construct message input
     *
     * @return Message input
     */
    @Bean
    public BufferedReader getMessageInput() {
        return new BufferedReader(new InputStreamReader(System.in));
    }

}
