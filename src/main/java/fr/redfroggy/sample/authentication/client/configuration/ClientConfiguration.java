package fr.redfroggy.sample.authentication.client.configuration;

import fr.redfroggy.sample.authentication.commons.security.Algorithm;
import fr.redfroggy.sample.authentication.commons.security.CipherService;
import fr.redfroggy.sample.authentication.commons.utils.BytesUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

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
    public CipherService getClientCipher() throws GeneralSecurityException {
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

    /**
     * Construct key pair for RSA algorithm
     *
     * @return Key pair
     */
    @Bean
    public KeyPair getKeyPair() throws GeneralSecurityException {
        if (Algorithm.RSA.equals(Algorithm.valueOf(keySettings.getAlgorithm()))) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(Algorithm.valueOf(keySettings.getAlgorithm()).getKeyAlgorithm());
            keyGen.initialize(keySettings.getRsaKeySize());
            return keyGen.genKeyPair();
        }
        return null;
    }

}
