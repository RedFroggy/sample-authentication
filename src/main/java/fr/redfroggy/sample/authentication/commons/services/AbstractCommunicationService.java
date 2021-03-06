package fr.redfroggy.sample.authentication.commons.services;

import com.google.common.primitives.Bytes;
import fr.redfroggy.sample.authentication.commons.exceptions.CommunicationException;
import fr.redfroggy.sample.authentication.commons.security.CipherService;
import fr.redfroggy.sample.authentication.commons.utils.BytesUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Common methods for communication service (client and server)
 */
@Slf4j
public class AbstractCommunicationService {

    @Autowired
    protected CipherService cipherService;

    protected DataOutputStream out;

    protected InputStream in;

    protected static final int FRAME_SIZE = 64;

    /**
     * Send command to server and wait for response
     *
     * @param cmd Command to send
     * @return Receive bytes
     * @throws CommunicationException If a communication error occurred
     */
    protected byte[] send(byte[] cmd) throws CommunicationException {
        return send(cmd, true);
    }

    /**
     * Send command to server
     *
     * @param cmd             Command to send
     * @param waitForResponse Wait for response
     * @return Receive bytes
     * @throws CommunicationException If a communication error occurred
     */
    protected byte[] send(byte[] cmd, boolean waitForResponse) throws CommunicationException {
        try {
            out.write(cmd);
            log.info("Send: {} bytes | {} | {}", cmd.length, BytesUtils.bytesToHex(cmd, ' '), new String(cmd));
            if (waitForResponse) {
                return receive();
            } else {
                return new byte[0];
            }
        } catch (IOException e) {
            throw new CommunicationException("Sending error", e);
        }
    }

    /**
     * Listen for server response
     *
     * @return Receive bytes
     * @throws CommunicationException If a communication error occurred
     */
    protected byte[] receive() throws CommunicationException {
        try {
            byte[] result = new byte[0];
            int count;
            do {
                byte[] frame = new byte[FRAME_SIZE];
                count = in.read(frame);
                result = Bytes.concat(result, Arrays.copyOf(frame, count));
            } while (count >= FRAME_SIZE);
            log.info("Receive: {} bytes | {} | {}", result.length, BytesUtils.bytesToHex(result, ' '), new String(result));
            return result;
        } catch (IOException e) {
            throw new CommunicationException("Receiving error", e);
        }
    }

    /**
     * Set session key
     *
     * @param clientRandom Client random sequence
     * @param serverRandom Server random sequence
     * @throws GeneralSecurityException If a cryptographic error occurred
     */
    public void setSessionKey(byte[] clientRandom, byte[] serverRandom) throws GeneralSecurityException {

        log.debug("Build {} session key", cipherService.getAlgorithm());
        byte[] session;

        switch (cipherService.getAlgorithm()) {
            case DES:
                session = Bytes.concat(Arrays.copyOfRange(clientRandom, 0, 4), Arrays.copyOfRange(serverRandom, 0, 4));
                break;
            case TDES:
                session = Bytes.concat(Arrays.copyOfRange(clientRandom, 0, 4), Arrays.copyOfRange(serverRandom, 0, 4),
                        Arrays.copyOfRange(clientRandom, 4, 8), Arrays.copyOfRange(serverRandom, 4, 8));
                break;
            case AES:
                session = Bytes.concat(Arrays.copyOfRange(clientRandom, 0, 4), Arrays.copyOfRange(serverRandom, 0, 4),
                        Arrays.copyOfRange(clientRandom, 12, 16), Arrays.copyOfRange(serverRandom, 12, 16));
                break;
            case TKTDES:
                session = Bytes.concat(Arrays.copyOfRange(clientRandom, 0, 4), Arrays.copyOfRange(serverRandom, 0, 4),
                        Arrays.copyOfRange(clientRandom, 6, 10), Arrays.copyOfRange(serverRandom, 6, 10),
                        Arrays.copyOfRange(clientRandom, 12, 16), Arrays.copyOfRange(serverRandom, 12, 16));
                break;
            default:
                session = new byte[0];
                break;
        }

        cipherService.setKey(session);
    }
}
