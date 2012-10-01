package org.jose4j.jws;

import junit.framework.TestCase;
import junit.framework.Assert;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwx.CompactSerialization;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.keys.HmacKey;

import java.security.Key;

/**
 *
 */
public class HmacShaTest extends TestCase
{
    Key KEY1 = new HmacKey(new byte[]{41, -99, 60, 91, 49, 70, -99, -14, -108, -81, 60, 37, 104, -116, 106, 104, -2, -95, 56, 103, 64, 10, -56, 120, 37, -48, 6, 9, 110, -96, 27, -4});
    Key KEY2 = new HmacKey(new byte[]{-67, 34, -45, 50, 13, 84, -79, 114, -16, -44, 26, -39, 4, -1, 26, 9, 38, 78, -107, 39, -81, 75, -18, 38, 56, 34, 13, 78, -73, 62, -60, 52});

    public void testHmacSha256A()
    {
        testBasicRoundTrip("some content that is the payload", AlgorithmIdentifiers.HMAC_SHA256);
    }

    public void testHmacSha256B()
    {
        testBasicRoundTrip("{\"iss\":\"https://jwt-idp.example.com\",\n" +
                "    \"prn\":\"mailto:mike@example.com\",\n" +
                "    \"aud\":\"https://jwt-rp.example.net\",\n" +
                "    \"iat\":1300815780,\n" +
                "    \"exp\":1300819380,\n" +
                "    \"http://claims.example.com/member\":true}", AlgorithmIdentifiers.HMAC_SHA256);
    }

    public void testHmacSha384A()
    {
        testBasicRoundTrip("Looking good, Billy Ray!", AlgorithmIdentifiers.HMAC_SHA384);
    }

    public void testHmacSha348B()
    {
        testBasicRoundTrip("{\"meh\":\"meh\"}", AlgorithmIdentifiers.HMAC_SHA384);
    }

    public void testHmacSha512A()
    {
        testBasicRoundTrip("Feeling good, Louis!", AlgorithmIdentifiers.HMAC_SHA512);
    }

    public void testHmacSha512B()
    {
        testBasicRoundTrip("{\"meh\":\"mehvalue\"}", AlgorithmIdentifiers.HMAC_SHA512);
    }

    void testBasicRoundTrip(String payload, String jwsAlgo)
    {
        JsonWebSignature jwsWithKey1 = new JsonWebSignature();
        jwsWithKey1.setPayload(payload);
        jwsWithKey1.setAlgorithmHeaderValue(jwsAlgo);
        jwsWithKey1.setKey(KEY1);
        String serializationWithKey1 = jwsWithKey1.getCompactSerialization();

        JsonWebSignature jwsWithKey2 = new JsonWebSignature();
        jwsWithKey2.setKey(KEY2);        
        jwsWithKey2.setAlgorithmHeaderValue(jwsAlgo);
        jwsWithKey2.setPayload(payload);
        String serializationWithKey2 = jwsWithKey2.getCompactSerialization();
        validateBasicStructure(serializationWithKey1);
        validateBasicStructure(serializationWithKey2);
        assertFalse(serializationWithKey1.equals(serializationWithKey2));

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(serializationWithKey1);
        jws.setKey(KEY1);
        assertTrue(jws.verifySignature());
        assertEquals(payload, jws.getPayload());

        jws = new JsonWebSignature();
        jws.setCompactSerialization(serializationWithKey2);
        jws.setKey(KEY1);
        assertFalse(jws.verifySignature());

        jws = new JsonWebSignature();
        jws.setCompactSerialization(serializationWithKey2);
        jws.setKey(KEY2);
        assertTrue(jws.verifySignature());
        assertEquals(payload, jws.getPayload());

        jws = new JsonWebSignature();
        jws.setCompactSerialization(serializationWithKey1);
        jws.setKey(KEY2);
        assertFalse(jws.verifySignature());
    }

    void validateBasicStructure(String compactSerialization)
    {
        Assert.assertNotNull(compactSerialization);
        Assert.assertEquals(compactSerialization.trim(), compactSerialization);
        String[] parts = CompactSerialization.deserialize(compactSerialization);
        Assert.assertEquals(JsonWebSignature.COMPACT_SERIALIZATION_PARTS, parts.length);
    }
}