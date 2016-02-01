package fr.redfroggy.sample.authentication.commons.exceptions;

/**
 * Exception used when Communication process failed
 */
public class CommunicationException extends Exception {

    /**
     * Create an Communication exception
     */
    public CommunicationException(String message) {
        super(message);
    }

    /**
     * Create an Communication exception
     */
    public CommunicationException(String message, Throwable cause) {
        super(message, cause);
    }
}
