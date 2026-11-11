/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.catalina.authenticator;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.AuthStatus;
import jakarta.security.auth.message.MessageInfo;
import jakarta.security.auth.message.MessagePolicy;
import jakarta.security.auth.message.callback.PasswordValidationCallback;
import jakarta.security.auth.message.config.AuthConfigFactory;
import jakarta.security.auth.message.module.ServerAuthModule;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.authenticator.jaspic.AuthConfigFactoryImpl;
import org.apache.catalina.authenticator.jaspic.MessageInfoImpl;
import org.apache.catalina.authenticator.jaspic.SimpleAuthConfigProvider;
import org.apache.catalina.startup.TesterMapRealm;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;

/*
 * When a single Jakarta Authentication provider is registered for all web applications, each web application must
 * authenticate users with its own ServerAuthConfig (and hence its own CallbackHandler and Realm). Previously, the
 * ServerAuthConfig created for the first web application was cached by SimpleAuthConfigProvider and re-used by every
 * other web application, so users were validated against the Realm of the wrong web application.
 */
public class TestJaspicServerAuthConfigPerContext extends TomcatBaseTest {

    private static final String HTTP_PREFIX = "http://localhost:";

    private static final String SERVER_AUTH_MODULE_KEY_PREFIX =
            "org.apache.catalina.authenticator.jaspic.ServerAuthModule.";

    private static final String CONTEXT_PATH_A = "/a";
    private static final String CONTEXT_PATH_B = "/b";

    private static final String USER_A = "alice";
    private static final String PWD_A = "alice-pwd";
    private static final String USER_B = "bob";
    private static final String PWD_B = "bob-pwd";
    private static final String ROLE = "role";

    private static final String URI_PROTECTED = "/protected";
    private static final String URI_PROGRAMMATIC = "/programmatic";

    private static final AtomicInteger MODULE_INIT_COUNT = new AtomicInteger();

    private AuthConfigFactory factory;


    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        MODULE_INIT_COUNT.set(0);

        // Use a dedicated factory so registrations do not leak into other tests
        factory = new AuthConfigFactoryImpl();
        AuthConfigFactory.setFactory(factory);

        Map<String,Object> properties = new HashMap<>();
        properties.put(SERVER_AUTH_MODULE_KEY_PREFIX + "1", TesterBasicServerAuthModule.class.getName());
        // Registers the provider for all message layers and all application contexts
        new SimpleAuthConfigProvider(properties, factory);

        Tomcat tomcat = getTomcatInstance();
        addContext(tomcat, CONTEXT_PATH_A, USER_A, PWD_A);
        addContext(tomcat, CONTEXT_PATH_B, USER_B, PWD_B);
        tomcat.start();
    }


    @After
    @Override
    public void tearDown() throws Exception {
        try {
            super.tearDown();
        } finally {
            AuthConfigFactory.setFactory(null);
        }
    }


    @Test
    public void testContainerAuthenticationUsesRealmOfWebApplication() throws Exception {
        // First web application to use the provider
        doRequest(CONTEXT_PATH_A + URI_PROTECTED, USER_A, PWD_A, HttpServletResponse.SC_OK, USER_A);

        // A user of web application A must not be able to authenticate to web application B
        doRequest(CONTEXT_PATH_B + URI_PROTECTED, USER_A, PWD_A, HttpServletResponse.SC_UNAUTHORIZED, null);

        // Users of web application B must be validated against the Realm of web application B
        doRequest(CONTEXT_PATH_B + URI_PROTECTED, USER_B, PWD_B, HttpServletResponse.SC_OK, USER_B);

        // ... and must not be able to authenticate to web application A
        doRequest(CONTEXT_PATH_A + URI_PROTECTED, USER_B, PWD_B, HttpServletResponse.SC_UNAUTHORIZED, null);
        doRequest(CONTEXT_PATH_A + URI_PROTECTED, USER_A, PWD_A, HttpServletResponse.SC_OK, USER_A);

        // The ServerAuthConfig is cached per web application so the module is initialised once per web application
        Assert.assertEquals(2, MODULE_INIT_COUNT.get());
    }


    @Test
    public void testProgrammaticAuthenticationUsesRealmOfWebApplication() throws Exception {
        // First web application to use the provider
        doRequest(CONTEXT_PATH_A + URI_PROGRAMMATIC, USER_A, PWD_A, HttpServletResponse.SC_OK, USER_A);

        // A user of web application A must not be able to authenticate to web application B
        doRequest(CONTEXT_PATH_B + URI_PROGRAMMATIC, USER_A, PWD_A, HttpServletResponse.SC_UNAUTHORIZED, null);

        // Users of web application B must be validated against the Realm of web application B
        doRequest(CONTEXT_PATH_B + URI_PROGRAMMATIC, USER_B, PWD_B, HttpServletResponse.SC_OK, USER_B);
        doRequest(CONTEXT_PATH_A + URI_PROGRAMMATIC, USER_B, PWD_B, HttpServletResponse.SC_UNAUTHORIZED, null);
    }


    private void addContext(Tomcat tomcat, String contextPath, String user, String password) {
        Context ctx = tomcat.addContext(contextPath, null);

        // Protected by a security constraint so authentication is mandatory
        Tomcat.addServlet(ctx, "protected", new RemoteUserServlet(false));
        ctx.addServletMappingDecoded(URI_PROTECTED, "protected");
        SecurityCollection collection = new SecurityCollection();
        collection.addPatternDecoded(URI_PROTECTED);
        SecurityConstraint constraint = new SecurityConstraint();
        constraint.addAuthRole(ROLE);
        constraint.addCollection(collection);
        ctx.addConstraint(constraint);

        // Not protected so the servlet triggers authentication via HttpServletRequest.authenticate()
        Tomcat.addServlet(ctx, "programmatic", new RemoteUserServlet(true));
        ctx.addServletMappingDecoded(URI_PROGRAMMATIC, "programmatic");

        TesterMapRealm realm = new TesterMapRealm();
        realm.addUser(user, password);
        realm.addUserRole(user, ROLE);
        ctx.setRealm(realm);

        LoginConfig lc = new LoginConfig();
        lc.setAuthMethod("BASIC");
        ctx.setLoginConfig(lc);
        ctx.getPipeline().addValve(new BasicAuthenticator());
    }


    private void doRequest(String uri, String user, String password, int expectedRc, String expectedUser)
            throws Exception {
        Map<String,List<String>> reqHeaders = new HashMap<>();
        List<String> auth = new ArrayList<>();
        auth.add("Basic " +
                Base64.getEncoder().encodeToString((user + ":" + password).getBytes(StandardCharsets.ISO_8859_1)));
        reqHeaders.put("Authorization", auth);

        ByteChunk bc = new ByteChunk();
        int rc = getUrl(HTTP_PREFIX + getPort() + uri, bc, reqHeaders, null);

        Assert.assertEquals(uri + " " + user, expectedRc, rc);
        if (expectedUser != null) {
            Assert.assertEquals(uri + " " + user, expectedUser, bc.toString());
        }
    }


    private static final class RemoteUserServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        private final boolean programmatic;

        RemoteUserServlet(boolean programmatic) {
            this.programmatic = programmatic;
        }

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            if (programmatic && !req.authenticate(resp)) {
                // The ServerAuthModule has set the status code
                return;
            }
            resp.setContentType("text/plain");
            resp.setCharacterEncoding("UTF-8");
            resp.getWriter().print(req.getRemoteUser());
        }
    }


    /*
     * Minimal BASIC style module that validates the provided credentials via the CallbackHandler (and hence the Realm)
     * it was initialised with. Authentication is only performed when it is mandatory.
     */
    public static final class TesterBasicServerAuthModule implements ServerAuthModule {

        private CallbackHandler handler;

        @Override
        public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler,
                @SuppressWarnings("rawtypes") Map options) throws AuthException {
            this.handler = handler;
            MODULE_INIT_COUNT.incrementAndGet();
        }

        @Override
        public Class<?>[] getSupportedMessageTypes() {
            return new Class<?>[] { HttpServletRequest.class, HttpServletResponse.class };
        }

        @Override
        public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject)
                throws AuthException {
            if (!Boolean.parseBoolean((String) messageInfo.getMap().get(MessageInfoImpl.IS_MANDATORY))) {
                return AuthStatus.SUCCESS;
            }

            HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
            HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();

            String authorization = request.getHeader("Authorization");
            if (authorization != null && authorization.startsWith("Basic ")) {
                String decoded = new String(Base64.getDecoder().decode(authorization.substring(6)),
                        StandardCharsets.ISO_8859_1);
                int colon = decoded.indexOf(':');
                if (colon > 0) {
                    PasswordValidationCallback pvc = new PasswordValidationCallback(clientSubject,
                            decoded.substring(0, colon), decoded.substring(colon + 1).toCharArray());
                    try {
                        handler.handle(new Callback[] { pvc });
                    } catch (IOException | UnsupportedCallbackException e) {
                        throw new AuthException(e.getMessage(), e);
                    }
                    if (pvc.getResult()) {
                        return AuthStatus.SUCCESS;
                    }
                }
            }

            response.setHeader("WWW-Authenticate", "Basic realm=\"test\"");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return AuthStatus.SEND_FAILURE;
        }

        @Override
        public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
            return AuthStatus.SEND_SUCCESS;
        }

        @Override
        public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
            // NO-OP
        }
    }
}
