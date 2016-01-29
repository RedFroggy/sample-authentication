package fr.redfroggy.sample.tpa.commons.exceptions;

/**
 * Exception used when transmission process failed
 */
public class TransmissionException extends Exception {

    /**
     * Create an transmission exception
     */
    public TransmissionException(String message) {
        super(message);
    }

    /**
     * Create an transmission exception
     */
    public TransmissionException(String message, Throwable cause) {
        super(message, cause);
    }
}
