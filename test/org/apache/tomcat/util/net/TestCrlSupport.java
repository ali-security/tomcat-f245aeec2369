/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tomcat.util.net;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;

/**
 * Tests that a CRL configured on a connector is processed consistently by every TLS implementation.
 * <p>
 * The server key for these tests always comes from a Java key store (see
 * {@link TesterSupport#initSsl(Tomcat, boolean)}). The OpenSSL based implementations used to configure the CRL only
 * when the certificate and key were supplied as PEM files, so with a key store the CRL was silently dropped and the
 * connector ran with no revocation checking at all. The FFM implementation additionally only logged - rather than
 * reported - a CRL that could not be loaded, leaving the connector running with CRL checking requested but no CRL
 * loaded. Either way every revoked client certificate was accepted. A CRL that cannot be loaded must therefore be
 * reported rather than ignored.
 * <p>
 * Note: the {@code empty-crl.pem} and {@code populated-crl.pem} files are issued by a later generation of the Apache
 * Tomcat test CA than the one held in this branch's test key stores ({@code ca.jks} / {@code ca-cert.pem}), and the CA
 * private key is not part of the source tree so they cannot be re-issued here. They are structurally valid CRLs and
 * load correctly, which is what the code under test checks, but their signature cannot be verified against this
 * branch's CA. Asserting that a revoked client certificate is rejected is therefore not possible on this branch and
 * the {@code clientCertificateIsRevoked} dimension of the upstream test is omitted.
 */
@RunWith(Parameterized.class)
public class TestCrlSupport extends TomcatBaseTest {

    /*
     * A well formed PEM block that does not contain a valid CRL. Every TLS implementation has to reject it.
     */
    private static final String INVALID_CRL =
            "-----BEGIN X509 CRL-----\n" + "bm90LWEtdmFsaWQtQ1JM\n" + "-----END X509 CRL-----\n";

    @Parameters(name = "{0} with OpenSSL trust {2}, CRL {4}")
    public static Collection<Object[]> parameters() {
        List<Object[]> parameterSets = new ArrayList<>();
        for (Boolean crlIsPopulated : booleans) {
            parameterSets.add(new Object[] { "JSSE", Boolean.FALSE, Boolean.FALSE,
                    "org.apache.tomcat.util.net.jsse.JSSEImplementation", crlIsPopulated });
            parameterSets.add(new Object[] { "OpenSSL", Boolean.TRUE, Boolean.TRUE,
                    "org.apache.tomcat.util.net.openssl.OpenSSLImplementation", crlIsPopulated });
            parameterSets.add(new Object[] { "OpenSSL", Boolean.TRUE, Boolean.FALSE,
                    "org.apache.tomcat.util.net.openssl.OpenSSLImplementation", crlIsPopulated });
            parameterSets.add(new Object[] { "OpenSSL-FFM", Boolean.TRUE, Boolean.TRUE,
                    "org.apache.tomcat.util.net.openssl.panama.OpenSSLImplementation", crlIsPopulated });
            parameterSets.add(new Object[] { "OpenSSL-FFM", Boolean.TRUE, Boolean.FALSE,
                    "org.apache.tomcat.util.net.openssl.panama.OpenSSLImplementation", crlIsPopulated });
        }

        return parameterSets;
    }

    @Parameter(0)
    public String connectorName;

    @Parameter(1)
    public boolean useOpenSSL;

    @Parameter(2)
    public boolean useOpenSSLTrust;

    @Parameter(3)
    public String sslImplementationName;

    @Parameter(4)
    public boolean crlIsPopulated;


    @Override
    public void setUp() throws Exception {
        super.setUp();
        Tomcat tomcat = getTomcatInstance();
        TesterSupport.configureSSLImplementation(tomcat, sslImplementationName, useOpenSSL);
        TesterSupport.configureClientCertContext(tomcat, useOpenSSLTrust, TesterSupport.CLIENT_JKS,
                TesterSupport.CLIENT_CRL_JKS);
        // Configure the CRL
        if (crlIsPopulated) {
            tomcat.getConnector().findSslHostConfigs()[0].setCertificateRevocationListFile(
                    new File(TesterSupport.POPULATED_CRL).getAbsolutePath());
        } else {
            tomcat.getConnector().findSslHostConfigs()[0].setCertificateRevocationListFile(
                    new File(TesterSupport.EMPTY_CRL).getAbsolutePath());
        }
    }


    /*
     * A CRL that can be loaded has to be accepted. This is the control for testInvalidCrlIsNotIgnored() below. It
     * confirms that reporting a CRL that cannot be loaded does not also reject valid CRL configurations.
     */
    @Test
    public void testValidCrlIsAccepted() throws Exception {
        TesterSupport.configureClientSsl();

        getTomcatInstance().start();

        // Unprotected resource. No client certificate is required to access it.
        ByteChunk res = getUrl("https://localhost:" + getPort() + "/unprotected");
        Assert.assertEquals("OK", res.toString());
    }


    /*
     * A CRL that cannot be loaded must not be silently ignored. If it is, the connector starts with CRL checking
     * requested but no CRL loaded and every revoked client certificate is accepted. The failure has to be reported so
     * that the connector does not start.
     *
     * The server key here comes from a Java key store, so this also covers the case where the OpenSSL based
     * implementations skipped the CRL configuration entirely: without the fix the CRL file is never read, nothing
     * fails and the connector starts.
     */
    @Test
    public void testInvalidCrlIsNotIgnored() throws Exception {
        File invalidCrl = File.createTempFile("invalid-crl-", ".pem", getTemporaryDirectory());
        addDeleteOnTearDown(invalidCrl);
        Files.write(invalidCrl.toPath(), INVALID_CRL.getBytes(StandardCharsets.US_ASCII));

        Tomcat tomcat = getTomcatInstance();
        tomcat.getConnector().findSslHostConfigs()[0].setCertificateRevocationListFile(invalidCrl.getAbsolutePath());

        try {
            tomcat.start();
        } catch (LifecycleException e) {
            // Expected. The CRL could not be loaded and the failure was reported.
            return;
        }
        Assert.fail("Connector started with a CRL that could not be loaded");
    }
}
