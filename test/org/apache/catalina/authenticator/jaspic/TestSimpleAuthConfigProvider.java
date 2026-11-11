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
package org.apache.catalina.authenticator.jaspic;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import jakarta.security.auth.message.config.ServerAuthConfig;

import org.junit.Assert;
import org.junit.Test;

public class TestSimpleAuthConfigProvider {

    private static final String SERVER_AUTH_MODULE_KEY_PREFIX =
            "org.apache.catalina.authenticator.jaspic.ServerAuthModule.";

    private static final Map<String,Object> CONFIG_PROPERTIES;
    static {
        CONFIG_PROPERTIES = new HashMap<>();
        CONFIG_PROPERTIES.put(SERVER_AUTH_MODULE_KEY_PREFIX + "1", TesterServerAuthModuleA.class.getName());
    }


    /*
     * A provider registered for all application contexts must not hand the ServerAuthConfig (and hence the
     * CallbackHandler and the Realm) of the first web application that used it to every other web application.
     */
    @Test
    public void testServerAuthConfigNotSharedBetweenAppContexts() throws Exception {
        SimpleAuthConfigProvider provider = new SimpleAuthConfigProvider(CONFIG_PROPERTIES, null);

        CallbackHandler handlerA = callbacks -> {
            // NO-OP
        };
        CallbackHandler handlerB = callbacks -> {
            // NO-OP
        };

        ServerAuthConfig serverAuthConfigA = provider.getServerAuthConfig("HttpServlet", "localhost /a", handlerA);
        ServerAuthConfig serverAuthConfigB = provider.getServerAuthConfig("HttpServlet", "localhost /b", handlerB);

        Assert.assertNotNull(serverAuthConfigA);
        Assert.assertNotNull(serverAuthConfigB);
        Assert.assertNotSame(serverAuthConfigA, serverAuthConfigB);
        Assert.assertEquals("localhost /a", serverAuthConfigA.getAppContext());
        Assert.assertEquals("localhost /b", serverAuthConfigB.getAppContext());
    }
}
