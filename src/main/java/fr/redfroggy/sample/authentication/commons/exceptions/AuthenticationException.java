package fr.redfroggy.sample.authentication.commons.exceptions;

/**
 * Exception used when authentication process failed
 */
public class AuthenticationException extends Exception {

    /**
     * Create an authentication exception
     */
    public AuthenticationException(String message) {
        super(message);
    }

    /**
     * Create an authentication exception
     */
    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
