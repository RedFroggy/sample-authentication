package fr.redfroggy.sample.tpa.commons.exceptions;

/**
 * Exception used to close server socket (End Of Transmission)
 */
public class EOTException extends ServerException {

    /**
     * Create an EOT exception
     */
    public EOTException() {
        super("End of transmission");
    }
}
