package fr.redfroggy.sample.authentication.commons.security;

import com.google.common.primitives.Bytes;
import fr.redfroggy.sample.authentication.commons.utils.BytesUtils;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;

/**
 * Cipher service use for cryptographic process
 */
@Slf4j
public class CipherService {

    @Autowired
    @Getter
    protected KeyPair keyPair;

    protected PublicKey publicKey;

    @Getter
    protected Algorithm algorithm;

    protected Random randomizer = new Random();

    protected Cipher cipher;

    protected byte[] key;

    protected boolean resetIV = true;

    /**
     * Construct cipher
     *
     * @param algorithm Algorithm to use
     * @param key       Key to used
     */
    public CipherService(Algorithm algorithm, byte[] key) {
        this.algorithm = algorithm;

        try {
            if (!Algorithm.RSA.equals(algorithm)) {
                setKey(key);
            }
        } catch(GeneralSecurityException e) {
            log.error("Cannot initialise key", e);
        }
    }

    /**
     * Get random value with algorithm bloc size
     *
     * @return Random value
     */
    public byte[] random() {

        byte[] rndA = new byte[algorithm.getBlocSize()];
        randomizer.nextBytes(rndA);
        return rndA;
    }

    /**
     * Encode data with current key and algorithm
     *
     * @param data Data to encode
     * @return Encoded data
     * @throws GeneralSecurityException Is an error occurred during cryptographic process
     */
    public byte[] encode(byte[] data) throws GeneralSecurityException {
        byte[] toEncode = BytesUtils.pad(data, getAlgorithm().getBlocSize());
        return cipher(toEncode, Cipher.ENCRYPT_MODE);
    }


    /**
     * Decode data with current key and algorithm
     *
     * @param data Data to decode
     * @return Decoded data
     * @throws GeneralSecurityException Is an error occurred during cryptographic process
     */
    public byte[] decode(byte[] data) throws GeneralSecurityException {
        byte[] decoded = cipher(data, Cipher.DECRYPT_MODE);
        return BytesUtils.unpad(decoded);
    }

    /**
     * Reset init vector
     */
    public void resetIV() {
        resetIV = true;
    }

    /**
     * Process cryptographic operation
     *
     * @param data Data to process
     * @param type Type of process (Encode or Decode)
     * @return Proceed data
     * @throws GeneralSecurityException Is an error occurred during cryptographic process
     */
    protected byte[] cipher(byte[] data, int type) throws GeneralSecurityException {

        if (cipher == null) {
            cipher = Cipher.getInstance(algorithm.getCipherAlgorithm());
        }
        if (Algorithm.RSA.equals(algorithm) && Cipher.DECRYPT_MODE == type) {
            cipher.init(type, keyPair.getPrivate());
        } else if (Algorithm.RSA.equals(algorithm) && Cipher.ENCRYPT_MODE == type) {
            cipher.init(type, publicKey);
        } else if (resetIV) {
            cipher.init(type, new SecretKeySpec(key, algorithm.getKeyAlgorithm()), new IvParameterSpec(new byte[algorithm.getBlocSize()]));
        }

        return cipher.doFinal(data);
    }

    /**
     * Set a new key for cryptographic operations
     *
     * @param newKey New key
     * @throws GeneralSecurityException Is an error occurred during cryptographic process
     */
    public void setKey(byte[] newKey) throws GeneralSecurityException {

        if (Algorithm.RSA.equals(algorithm)) {
            publicKey = KeyFactory.getInstance(algorithm.getKeyAlgorithm()).generatePublic(new X509EncodedKeySpec(newKey));
        } else {
            resetIV();

            if (algorithm.equals(Algorithm.DES) && newKey.length == 8) {
                key = Bytes.concat(newKey, newKey, newKey);
            } else if ((algorithm.equals(Algorithm.DES) || algorithm.equals(Algorithm.TDES)) && newKey.length == 16) {
                key = Bytes.concat(newKey, Arrays.copyOf(newKey, 8));
            } else {
                key = newKey;
            }
        }
    }
}
