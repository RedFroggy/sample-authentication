package fr.redfroggy.sample.tpa.client.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Settings for socket
 */
@Component
@ConfigurationProperties
@Data
public class KeySettings {

    /**
     * Algorithm used for authentication
     */
    protected String algorithm = "AES";

    /**
     * Symmetric key
     */
    protected String key = "00112233445566778899AABBCCDDEEFF";

}
