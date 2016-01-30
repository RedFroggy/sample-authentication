package fr.redfroggy.sample.authentication.commons.exceptions;

/**
 * Exception used when server error occurred
 */
public class ServerException extends Exception {

    /**
     * Create an server exception
     */
    public ServerException(String message) {
        super(message);
    }

    /**
     * Create an server exception
     */
    public ServerException(String message, Throwable cause) {
        super(message, cause);
    }
}
