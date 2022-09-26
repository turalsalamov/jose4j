package org.jose4j.jwk;

import org.jose4j.keys.EdDsaKeyUtil;
import org.jose4j.lang.JoseException;

import java.security.KeyPair;
import java.security.SecureRandom;

public class OkpJwkGenerator
{
    public static OctetKeyPairJsonWebKey generateJwk(String subtype) throws JoseException
    {
        return generateJwk(subtype, null, null);
    }

    public static OctetKeyPairJsonWebKey generateJwk(String subtype, String provider, SecureRandom secureRandom)
            throws JoseException
    {
        EdDsaKeyUtil edDsaKeyUtil = new EdDsaKeyUtil(provider, secureRandom);
        KeyPair kp = edDsaKeyUtil.generateKeyPair(subtype);
        OctetKeyPairJsonWebKey okpJwk = (OctetKeyPairJsonWebKey) PublicJsonWebKey.Factory.newPublicJwk(kp.getPublic());
        okpJwk.setPrivateKey(kp.getPrivate());
        return okpJwk;
    }
}
