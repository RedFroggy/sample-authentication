package fr.redfroggy.sample.authentication.server.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Settings for socket
 */
@Component
@ConfigurationProperties
@Data
public class SocketSettings {

    /**
     * Serve port
     * default: 12345
     */
    protected int port = 12345;

}
