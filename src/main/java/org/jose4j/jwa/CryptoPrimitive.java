package org.jose4j.jwa;


import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.security.Signature;

/**
 * A wrapper class for a crypto primitive object, such as {@link Signature} and {@link Mac}, which helps
 * them transcend abstraction layers to be accessed in places they arguably should't be.
 */
public class CryptoPrimitive
{
    private final Signature sig;
    private final Cipher cip;
    private final Mac mac;

    public CryptoPrimitive(Signature sig)
    {
        this(sig, null, null);
    }

    public CryptoPrimitive(Cipher cipher)
    {
        this(null, cipher, null);
    }

    public CryptoPrimitive(Mac mac)
    {
        this(null, null, mac);
    }

    private CryptoPrimitive(Signature sig, Cipher cip, Mac mac)
    {
        this.sig = sig;
        this.cip = cip;
        this.mac = mac;
    }

    /**
     * Get the {@link Signature} object.
     *
     * @return {@link Signature} object or null if this wrapper doesn't have one.
     */
    public Signature getSignature() {
        return sig;
    }

    /**
     * Get the {@link Cipher} object.
     *
     * @return {@link Cipher} object or null if this wrapper doesn't have one.
     */
    public Cipher getCipher() {
        return cip;
    }

    /**
     * Get the {@link Mac} object.
     *
     * @return {@link Mac} object or null if this wrapper doesn't have one.
     */
    public Mac getMac() {
        return mac;
    }
}
