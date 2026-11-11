/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.realm;

import java.security.Principal;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.List;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.startup.LoggingBaseTest;
import org.apache.tomcat.util.compat.JreCompat;

public class TestDataSourceRealm extends LoggingBaseTest {

    public static final String SIMPLE_SCHEMA =
            "create table users (\n"
            + "  user_name         varchar(15) not null primary key,\n"
            + "  user_pass         varchar(15) not null\n"
            + ");\n"
            + "create table user_roles (\n"
            + "  user_name         varchar(15) not null,\n"
            + "  role_name         varchar(15) not null,\n"
            + "  primary key (user_name, role_name)\n"
            + ");";
    public static final String USERS_INSERT = "INSERT INTO users(user_name, user_pass) VALUES(?, ?)";
    public static final String ROLES_INSERT = "INSERT INTO user_roles(user_name, role_name) VALUES(?, ?)";

    protected class DerbyDataSourceRealm extends DataSourceRealm {
        protected final String name;
        protected Connection connection = null;
        public DerbyDataSourceRealm(String name) {
            this.name = "/" + name;
        }
        @Override
        protected Connection open() {
            // Replace DataSource use and JNDI access with direct Derby
            // connection
            if (connection == null) {
                try {
                    Class.forName("org.apache.derby.jdbc.EmbeddedDriver");
                    connection = DriverManager.getConnection("jdbc:derby:" + getTemporaryDirectory().getAbsolutePath()
                            + name + ";create=true");
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            }
            return connection;
        }
        @Override
        protected void close(Connection dbConnection) {
            // Only one connection so don't close it here
        }
        @Override
        public void initInternal() throws LifecycleException {
            // Avoid heavy lifecycle and JMX, however container log is needed
            containerLog = log;
        }
        @Override
        public void stopInternal() throws LifecycleException {
            super.stopInternal();
            if (connection != null) {
                super.close(connection);
            }
        }
    }

    private DerbyDataSourceRealm db;

    @Test
    public void testRealm() throws Exception {

        Assume.assumeTrue(JreCompat.isJre16Available());

        db = new DerbyDataSourceRealm("dsRealm");
        db.setUserTable("users");
        db.setUserNameCol("user_name");
        db.setUserCredCol("user_pass");
        db.setUserRoleTable("user_roles");
        db.setRoleNameCol("role_name");

        // First create the users and roles tables
        Connection connection = db.open();
        for (String sql: SIMPLE_SCHEMA.split(";")) {
            try (Statement statement = connection.createStatement()) {
                statement.execute(sql);
            }
        }

        try (PreparedStatement stmt = connection.prepareStatement(USERS_INSERT)) {
            stmt.setString(1, "tomcat");
            stmt.setString(2, "password");
            stmt.executeUpdate();
            stmt.setString(1, "random");
            stmt.setString(2, "password");
            stmt.executeUpdate();
        }
        try (PreparedStatement stmt = connection.prepareStatement(ROLES_INSERT)) {
            stmt.setString(1, "tomcat");
            stmt.setString(2, "admin");
            stmt.executeUpdate();
            stmt.setString(1, "tomcat");
            stmt.setString(2, "foo");
            stmt.executeUpdate();
        }

        db.start();

        Principal p = db.authenticate("tomcat", "bar");
        Assert.assertNull(p);

        p = db.authenticate("blabla", "bar");
        Assert.assertNull(p);

        p = db.authenticate("tomcat", "password");
        Assert.assertTrue(p instanceof GenericPrincipal);
        GenericPrincipal gp = (GenericPrincipal) p;
        Assert.assertTrue(gp.hasRole("foo"));
        Assert.assertTrue(gp.hasRole("admin"));
        Assert.assertFalse(gp.hasRole("manager"));

        p = db.getPrincipal("tomcat");
        Assert.assertTrue(p instanceof GenericPrincipal);
        gp = (GenericPrincipal) p;
        Assert.assertTrue(gp.hasRole("foo"));
        Assert.assertTrue(gp.hasRole("admin"));
        Assert.assertFalse(gp.hasRole("manager"));

        String pass = db.getPassword("tomcat");
        Assert.assertEquals("password", pass);

        List<String> roles = db.getRoles("tomcat");
        Assert.assertEquals(2, roles.size());

        p = db.getPrincipal("blabla");
        Assert.assertNull(p);

        p = db.getPrincipal("random");
        Assert.assertTrue(p instanceof GenericPrincipal);
        gp = (GenericPrincipal) p;
        Assert.assertEquals(0, gp.getRoles().length);

        db.stop();
    }


    @Test
    public void testRoleLookupFailure() throws Exception {

        Assume.assumeTrue(JreCompat.isJre16Available());

        DerbyDataSourceRealm realm = new DerbyDataSourceRealm("dsRealmRoleLookupFailure");
        realm.setUserTable("users");
        realm.setUserNameCol("user_name");
        realm.setUserCredCol("user_pass");
        // The role table is never created so every role lookup fails
        realm.setUserRoleTable("user_roles");
        realm.setRoleNameCol("role_name");

        // Only create the users table
        Connection connection = realm.open();
        try (Statement statement = connection.createStatement()) {
            statement.execute(SIMPLE_SCHEMA.split(";")[0]);
        }
        try (PreparedStatement stmt = connection.prepareStatement(USERS_INSERT)) {
            stmt.setString(1, "tomcat");
            stmt.setString(2, "password");
            stmt.executeUpdate();
        }

        realm.start();
        try {
            // Valid credentials but the role lookup fails so authentication must fail
            Assert.assertNull(realm.authenticate("tomcat", "password"));
            Assert.assertNull(realm.authenticate("tomcat"));
            Assert.assertNull(realm.getPrincipal("tomcat"));
            Assert.assertNull(realm.getRoles("tomcat"));
        } finally {
            realm.stop();
        }
    }


    @Test
    public void testAuthenticationOnly() throws Exception {

        Assume.assumeTrue(JreCompat.isJre16Available());

        DerbyDataSourceRealm realm = new DerbyDataSourceRealm("dsRealmAuthOnly");
        realm.setUserTable("users");
        realm.setUserNameCol("user_name");
        realm.setUserCredCol("user_pass");
        // No role store is configured
        realm.setAllRolesMode("authOnly");

        Connection connection = realm.open();
        try (Statement statement = connection.createStatement()) {
            statement.execute(SIMPLE_SCHEMA.split(";")[0]);
        }
        try (PreparedStatement stmt = connection.prepareStatement(USERS_INSERT)) {
            stmt.setString(1, "tomcat");
            stmt.setString(2, "password");
            stmt.executeUpdate();
        }

        realm.start();
        try {
            Assert.assertNull(realm.authenticate("tomcat", "bar"));
            Assert.assertNull(realm.authenticate("blabla", "password"));
            Assert.assertNull(realm.authenticate("blabla"));

            Principal p = realm.authenticate("tomcat", "password");
            Assert.assertTrue(p instanceof GenericPrincipal);
            Assert.assertEquals(0, ((GenericPrincipal) p).getRoles().length);

            p = realm.authenticate("tomcat");
            Assert.assertTrue(p instanceof GenericPrincipal);
            Assert.assertEquals(0, ((GenericPrincipal) p).getRoles().length);
        } finally {
            realm.stop();
        }
    }


    @Test
    public void testDatabaseUnavailable() throws Exception {

        DataSourceRealm realm = new DataSourceRealm() {
            {
                containerLog = log;
            }
            @Override
            protected Connection open() {
                // Simulate the database being unavailable
                return null;
            }
        };

        Assert.assertNull(realm.authenticate("tomcat", "password"));
        // Username only authentication (e.g. CLIENT-CERT, SPNEGO) must fail
        Assert.assertNull(realm.authenticate("tomcat"));
        Assert.assertNull(realm.getPrincipal("tomcat"));
    }
}
