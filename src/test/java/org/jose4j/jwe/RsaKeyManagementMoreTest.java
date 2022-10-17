package org.jose4j.jwe;

import org.jose4j.jwa.JceProviderTestSupport;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.junit.Assert;
import org.junit.Test;

public class RsaKeyManagementMoreTest
{

    @Test
    public void testSomeRoundTrips() throws Exception
    {
        RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);

        for (String alg : new String[] {KeyManagementAlgorithmIdentifiers.RSA1_5, KeyManagementAlgorithmIdentifiers.RSA_OAEP, KeyManagementAlgorithmIdentifiers.RSA_OAEP_256})
        {
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setAlgorithmHeaderValue(alg);
            jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
            jwe.setPayload("stuff");
            jwe.setKey(rsaJsonWebKey.getPublicKey());
            String compactSerialization = jwe.getCompactSerialization();

            jwe = new JsonWebEncryption();
            jwe.setCompactSerialization(compactSerialization);
            jwe.setKey(rsaJsonWebKey.getPrivateKey());
            Assert.assertEquals("stuff", jwe.getPlaintextString());
        }
    }

    @Test
    public void testSomeDecryptingWithTwoProviders() throws Exception
    {
        String jwkJson = "{\"kty\":\"RSA\"," +
               "\"n\":\"y_8p-sv8jFr5vFRvbVFOHBYQimII37mafhqZ7N__K-UbSTLysEa5gJeJb9SeAshsbzduWUnIks1v6zZ7PjyPKZcN9yi" +
                "3WRhK5TaTWZCmalqW3Pbz1POj0cEMJcxj6pYVxAGfOohNlPgfxyAQN3AnZG_dgu7F4LsRMnnlqkDHLqtRy3QijflAKP6gAHWIL" +
                "0xBGrMR0Rj_oLjKE-hk0QHgR0QNKXf4Nq8SgKazr9pzvm0dpb_shb5yEDp6agADleR6-KIcWd_bLWPsFzD1Ut9BgYkvRcKRICE" +
                "Or6uZwMtblW27TkLhcmc_7eFr0FH9g13KPD3GY_rYw92FFY1W1bVJlw\"," +
                "\"e\":\"AQAB\",\"d\":\"L2YI34ShGA2VZExsHYbcMstvqW-w5ybNfkp5BGBhflX7-oyTdiDgvj-3h9vroPLnuwmyop1xtKZ" +
                "2QD1G8oWIsB2weYKk41cxI8QEBbYF7MVCs3HP4uV_ZV_JDklI1_tqcEH-OM_t0tS6MX7CNddh18TkP6VyJc7hZoyLL_1gKnfqy" +
                "7nHMhr6UYUAucp2Db3tKqyj2SUB8h19QBlOUEc2yd0K1phWGGnGhME0uDRFJSiaaifsNxxbGbiFgp_d_nXvZzqjzWWjSBhkTRN" +
                "zL_JtQ9Y_nZJcuuhOAQL-WuC2yMrRPa0IHkwmvDtDxORhkx7V7gqx_1GXEaNGT94aPQT9rQ\",\"p\":\"3nCR0welBDxlOkAa" +
                "upt8IX49dkM_kzNZqxJXxbNwaJhh9EPN1sSU9cyvi3zxtVFgC9xLNaMDrSkUAu_vU14DuyyioaIXAP4pnbQTN6XqDL5kFzosi3" +
                "PaHsSCYHAcncY4TDnFqqjHnCSYKw_8nd819BezXq-NA1LQwLZjMi2YUAs\",\"q\":\"6sZCUKt9BUCtbtD8mfH-DfcyAehD1w" +
                "t-uJAGt3uNs1i1lb0JQ8mtH4KRpgK6HoGIK_30AZrKiPN_E8XLpi9BNWRRzkErs7cluNbebHXHqwcwos22An2zIVtAxVms-Tah" +
                "7XZHM5Z8fpExpjlZk7tzIHX7ltG_RX7_b64yo8SQKCU\",\"dp\":\"b8xuTn16H93nFtbfWEkLo53acFUuX-KgP84xVUlxxvB" +
                "H00g87aPSJpRg6p-6sGIc_vkSx_uNvnt19l_3jpQjFfFCMDDSlQopinzWZ9K5BvyuO8peVxy8VVh5GtVeXKIi65Th13uLD9yIq" +
                "qQXWJW2fV9oJL_hBPmbuDAzPSYTdq8\",\"dq\":\"e5ugxKpVa5OO_J5psH_Ze-7fVGO-fBVgRboG30nc5EVbbZgWrascTE_J" +
                "cXdUGMWoNUlC1Cl0Y0CYcoecXkXY9kx4SbjEUp2l7biraL1mP-TMNZtLLeqSiohqBL3fNWMPRGAWwtGDgHvfgR4GzKJPzhJwQQ" +
                "rzwppH0LwNi23tXEU\",\"qi\":\"wulvYLml_z8todGstRtwRDfI0vElBw2TR0x9V7XPmqZoVeKrySimVfccPGa6owfGC4wuu" +
                "_f-Dzdotk8BILHzKCyviLEIpN0d_OXEN14elAF8XjysL0bSg9tynxoYmdHs7GllDJHvy5HOcs_yuPmnkPvyP82kQy8xbr9nJuA" +
                "3L8Q\"}";

        final PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(jwkJson);

        final String jwe15 = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.K8XnfAap3iEz-PNojjoG6EEykHIqeBjNIL" +
                "5FV4bNTV8CiXG7VMVrL3XD7CnB-JRpeI0bgG46246AndJzg4HzINrY1TjlfdoPDCNsWbw2xyXVTLU7N1F8LjrtIpi8SwKm5DsEi" +
                "JBFbFpehE7fKi_op9eRkMrYO0TFGelWjMkSEo-yS2Tk46kfz-6EXdOdpo5bU6xGQ_dPA3Hl2c2g6cq8m7H3katE5LkQ2rpTcYDn" +
                "auwApb0CdZcWkOmC3xpGT89sGFMVOU5g1yRdGb40C_9-gdG9gFdoP4G5qW76he0KaSrdzXUGT_Z6EXGehj0B_bEes-L2sALROq_" +
                "0qKqiLkETRA.a74pDKBLkBr3ckxo2IW3fQ.hFlfVzjCNVCXiJ4J6sDHvA.giqvfcovD9D0f5A_faBVOQ";
        final String jweO = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ.eJYoF3gHsJKqguSLhtFH8d9Ovsvk_Zbt" +
                "sM3h2naWLgMpQ1KivgQPncWicGjEqb7yl1xk7A5t2gC1g_DJkKsoAORLJG3d2JlC58c5VOjijAUQHqYou_ccmbIVRlj7q1x8P6u" +
                "Kgg5qrpZOstwlSzo8BFhLCVtyu8LXvy2agDRarp-qBytFbPSzKEkZCpRLlsimRxA329bVSwBqHzldTEy-iyeq8rilSqk4ZbRcRk" +
                "QOcf8hwPOOh0ypRJDX3f2TykNUHAcxrZREtDghMerJo4tgJyvPr2JKwK4O9BOfmya-LBxToa7sBy9R82DdqhSqGAWEItyiNKFhi" +
                "HooRMsIkgwNyw.XxVEmEuUzmGRc4mcC5siJQ.42xjNf15bd1FyB2-S79LLA.ln-qHy1AheX-sI0K_86Awg";
        final String jweO2 = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.xsj_3GCVi6qvrIZf0PmXYsOjBo" +
                "lsjpsaxxEMNovkLKJQa_6AMncztzLi3kctMicqV-38Ye-9pwGZYmxCkOGO0jSIKKAMowjD-HyqBgaR27bDl7R0CXV0pb_N2gjfb" +
                "IuxYOT77paLBxuu2tJYfkYi3HqC2rPF3Qm8hcgvrLYJAb_DanGonPcThrlYHoj9LuVeusxMvjj2DS-zZq35woSv3Hru4M4nPvT0" +
                "YB5RHUAasP26pdRod5I0ov9GDd7KPR170oOrjRsVu7gZiEZFJLUmNAP9tucF3y15dDxj-87h9k5-a9io7ftHUAHgdSvP53fA1ZR" +
                "qsPa5U-CsGGCxqytO4A.6gIDMTcnGfZabZKVM5tVGg.MHdKv34aT-JpWYIvVBjE_A.pRJ4H2M2tybSvnkI4pi2GA";

        for (String jweString : new String[] {jwe15, jweO, jweO2})
        {
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setCompactSerialization(jweString);
            jwe.setKey(jwk.getPrivateKey());
            Assert.assertEquals("meh mode", jwe.getPlaintextString());
        }

        JceProviderTestSupport jceProviderTestSupport = new JceProviderTestSupport();
        jceProviderTestSupport.setUseBouncyCastleRegardlessOfAlgs(true);
        jceProviderTestSupport.runWithBouncyCastleProviderIfNeeded(new JceProviderTestSupport.RunnableTest()
        {
            @Override
            public void runTest() throws Exception
            {
                for (String jweString : new String[] {jwe15, jweO, jweO2})
                {
                    JsonWebEncryption jwe = new JsonWebEncryption();
                    jwe.setCompactSerialization(jweString);
                    jwe.setKey(jwk.getPrivateKey());
                    Assert.assertEquals("meh mode", jwe.getPlaintextString());
                }
            }
        });
    }


}
