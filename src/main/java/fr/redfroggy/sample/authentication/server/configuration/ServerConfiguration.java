package fr.redfroggy.sample.authentication.server.configuration;

import fr.redfroggy.sample.authentication.commons.security.Algorithm;
import fr.redfroggy.sample.authentication.commons.security.CipherService;
import fr.redfroggy.sample.authentication.commons.utils.BytesUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.net.ServerSocket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

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
    public CipherService getServerCipher() throws GeneralSecurityException {
        Algorithm algorithm = Algorithm.valueOf(keySettings.getAlgorithm());
        byte[] key = BytesUtils.hexToBytes(keySettings.getKey());
        return new CipherService(algorithm, key);
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
