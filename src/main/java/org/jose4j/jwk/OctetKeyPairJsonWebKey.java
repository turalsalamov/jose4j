package org.jose4j.jwk;

import org.jose4j.base64url.Base64Url;
import org.jose4j.keys.EdDsaKeyUtil;
import org.jose4j.lang.JoseException;

import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.EdECKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;


public class OctetKeyPairJsonWebKey extends PublicJsonWebKey
{
    static final Set<String> APPLICABLE_KEY_ALGORITHMS = new HashSet<>(Arrays.asList(EdDsaKeyUtil.ED448, EdDsaKeyUtil.ED25519, "EdDSA"));

    public static final String KEY_TYPE = "OKP";
    public static final String SUBTYPE_MEMBER_NAME = "crv";
    public static final String PUBLIC_KEY_MEMBER_NAME = "x";
    public static final String PRIVATE_KEY_MEMBER_NAME = "d";

    public static final String SUBTYPE_ED25519 = EdDsaKeyUtil.ED25519;
    public static final String SUBTYPE_ED448 = EdDsaKeyUtil.ED448;

    private final String subtype;

    public OctetKeyPairJsonWebKey(PublicKey publicKey)
    {
        super(publicKey);
        EdECKey edECKey = (EdECKey) publicKey;
        subtype = edECKey.getParams().getName();
    }

    public OctetKeyPairJsonWebKey(Map<String, Object> params) throws JoseException
    {
        this(params, null);
    }

    public OctetKeyPairJsonWebKey(Map<String, Object> params, String jcaProvider) throws JoseException
    {
        super(params, jcaProvider);

        subtype = getString(params, SUBTYPE_MEMBER_NAME, true);

        EdDsaKeyUtil edDsaKeyUtil = new EdDsaKeyUtil(jcaProvider, null);

        String encodedX = getString(params, PUBLIC_KEY_MEMBER_NAME, true);
        byte[] x = Base64Url.decode(encodedX);
        key = edDsaKeyUtil.publicKey(x, subtype);
        checkForBareKeyCertMismatch();

        if (params.containsKey(PRIVATE_KEY_MEMBER_NAME))
        {
            String encodedD = getString(params, PRIVATE_KEY_MEMBER_NAME, false);
            byte[] d = Base64Url.decode(encodedD);
            privateKey = edDsaKeyUtil.privateKey(d, subtype);
        }

        removeFromOtherParams(SUBTYPE_MEMBER_NAME, PUBLIC_KEY_MEMBER_NAME, PRIVATE_KEY_MEMBER_NAME);
    }

    static boolean isApplicable(Key key)
    {
        return APPLICABLE_KEY_ALGORITHMS.contains(key.getAlgorithm());
    }

    @Override
    public String getKeyType()
    {
        return KEY_TYPE;
    }

    public String getSubtype()
    {
        return subtype;
    }

    @Override
    protected String produceThumbprintHashInput()
    {
        String template = "{\"crv\":\"%s\",\"kty\":\"OKP\",\"x\":\"%s\"}";
        HashMap<String, Object> params = new HashMap<>();
        fillPublicTypeSpecificParams(params);
        Object crv = params.get(SUBTYPE_MEMBER_NAME);
        Object x = params.get(PUBLIC_KEY_MEMBER_NAME);
        return String.format(template, crv, x);
    }

    @Override
    protected void fillPublicTypeSpecificParams(Map<String, Object> params)
    {
        EdDsaKeyUtil edDsaKeyUtil = new EdDsaKeyUtil();
        byte[] publicKeyBytes = edDsaKeyUtil.rawPublicKey(this.key);
        params.put(SUBTYPE_MEMBER_NAME, subtype);
        params.put(PUBLIC_KEY_MEMBER_NAME, Base64Url.encode(publicKeyBytes));
    }

    @Override
    protected void fillPrivateTypeSpecificParams(Map<String, Object> params)
    {
        if (privateKey != null)
        {
            EdDsaKeyUtil edDsaKeyUtil = new EdDsaKeyUtil();
            byte[] privateKeyBytes = edDsaKeyUtil.rawPrivateKey(privateKey);
            params.put(PRIVATE_KEY_MEMBER_NAME, Base64Url.encode(privateKeyBytes));
        }
    }
}
