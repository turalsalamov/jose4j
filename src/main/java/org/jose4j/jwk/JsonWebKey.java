/*
 * Copyright 2012 Brian Campbell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jose4j.jwk;

import org.jose4j.lang.JoseException;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JsonHelp;

import java.io.Serializable;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.HashMap;

/**
 */
public abstract class JsonWebKey implements Serializable
{
    public static final String KEY_TYPE_PARAMETER = "kty";
    public static final String USE_PARAMETER = "use";
    public static final String KEY_ID_PARAMETER = "kid";
    public static final String ALGORITHM_PARAMETER = "alg";

    private String use;
    private String keyId;
    private String algorithm;

    protected PublicKey publicKey;

    protected JsonWebKey(PublicKey publicKey)
    {
        this.publicKey = publicKey;
    }

    protected JsonWebKey(Map<String, Object> params)
    {
        setUse(JsonHelp.getString(params, USE_PARAMETER));
        setKeyId(JsonHelp.getString(params, KEY_ID_PARAMETER));
        setAlgorithm(JsonHelp.getString(params, ALGORITHM_PARAMETER));
    }

    public abstract String getKeyType();
    protected abstract void fillTypeSpecificParams(Map<String,Object> params);

    public String getUse()
    {
        return use;
    }

    public void setUse(String use)
    {
        this.use = use;
    }

    public String getKeyId()
    {
        return keyId;
    }

    public void setKeyId(String keyId)
    {
        this.keyId = keyId;
    }

    public String getAlgorithm()
    {
        return algorithm;
    }

    public void setAlgorithm(String algorithm)
    {
        this.algorithm = algorithm;
    }

    public PublicKey getPublicKey()
    {
        return publicKey;
    }

    public Map<String, Object> toParams()
    {
        Map<String, Object> params = new LinkedHashMap<String, Object>();
        params.put(KEY_TYPE_PARAMETER, getKeyType());
        putIfNotNull(USE_PARAMETER, getUse(), params);
        putIfNotNull(KEY_ID_PARAMETER, getKeyId(), params);
        putIfNotNull(ALGORITHM_PARAMETER, getAlgorithm(), params);
        fillTypeSpecificParams(params);
        return params;
    }

    public String toJson()
    {
        Map<String, Object> params = toParams();
        return JsonUtil.toJson(params);
    }

    @Override
    public String toString()
    {
        return getClass().getName() + toParams();
    }

    protected void putIfNotNull(String name, String value, Map<String, Object> params)
    {
        if (value != null)
        {
            params.put(name,value);
        }
    }

    public static class Factory
    {
        public static JsonWebKey newJwk(Map<String,Object> params) throws JoseException
        {
            String alg = JsonHelp.getString(params, KEY_TYPE_PARAMETER);

            if (RsaJsonWebKey.KEY_TYPE.equals(alg))
            {
                return new RsaJsonWebKey(params);
            }
            else if (EllipticCurveJsonWebKey.KEY_TYPE.equals(alg))
            {
                return new EllipticCurveJsonWebKey(params);
            }
            else  if (PkixJsonWebKey.KEY_TYPE.equals(alg))
            {
                return new PkixJsonWebKey(params);
            }
            else
            {
                throw new JoseException("Unknown key algorithm: " + alg);
            }
        }

        public static JsonWebKey newJwk(PublicKey publicKey) throws JoseException
        {
            if (RSAPublicKey.class.isInstance(publicKey))
            {
                return new RsaJsonWebKey((RSAPublicKey)publicKey);
            }
            else if (ECPublicKey.class.isInstance(publicKey))
            {
                return new EllipticCurveJsonWebKey((ECPublicKey)publicKey);
            }
            else
            {
                throw new JoseException("Unsupported or unknown public key " + publicKey);
            }
        }

        public static JsonWebKey newJwk(String json) throws JoseException
        {
            Map<String, Object> parsed = JsonUtil.parseJson(json);
            return newJwk(parsed);
        }
    }
}