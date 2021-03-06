package fr.redfroggy.sample.authentication.server.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Settings for key
 */
@Component
@ConfigurationProperties
@Data
public class KeySettings {

    /**
     * Algorithm used for authentication
     * default: AES
     */
    protected String algorithm = "AES";

    /**
     * Symmetric key
     * default: 00112233445566778899AABBCCDDEEFF
     */
    protected String key = "00112233445566778899AABBCCDDEEFF";

    /**
     * RSA key size
     * default: 2048
     */
    protected int rsaKeySize = 2048;
}
