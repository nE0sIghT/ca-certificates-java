/*
 * Copyright (C) 2012 Damien Raude-Morvan <drazzib@debian.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

package org.debian.security;

import java.io.File;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Tests for {@link UpdateCertificates}.
 *
 * @author Damien Raude-Morvan
 */
public class UpdateCertificatesTest {

    private static final String ALIAS_CACERT   = "debian:spi-cacert-2008.crt";
    private static final String INVALID_CACERT = "x/usr/share/ca-certificates/spi-inc.org/spi-cacert-2008.crt";
    private static final String REMOVE_CACERT  = "-/usr/share/ca-certificates/spi-inc.org/spi-cacert-2008.crt";
    private static final String ADD_CACERT     = "+/usr/share/ca-certificates/spi-inc.org/spi-cacert-2008.crt";

    private String ksFilename;
    private String ksPassword;

    @Before
    public void start() {
        ksFilename = "./tests-cacerts";
        ksPassword = "changeit";
        // Delete any previous file
        File keystore = new File(ksFilename);
        keystore.delete();
    }

    /**
     * Test a simple open then write without any modification.
     */
    @Test
    public void testNoop() throws Exception {
        UpdateCertificates uc = new UpdateCertificates(ksPassword, ksFilename);
        uc.writeKeyStore();
    }

    /**
     * Test a to open a keystore and write without any modification
     * and then try to open it again with wrong password : will throw a
     * InvalidKeystorePassword
     */
    @Test
    public void testWriteThenOpenWrongPwd() throws Exception {
        try {
            UpdateCertificates uc = new UpdateCertificates(ksPassword, ksFilename);
            uc.writeKeyStore();
        } catch (InvalidKeystorePasswordException e) {
            fail();
        }

        try {
            UpdateCertificates uc = new UpdateCertificates("wrongpassword", ksFilename);
            fail();
            uc.writeKeyStore();
        } catch (InvalidKeystorePasswordException e) {
            assertEquals("Cannot open Java keystore. Is the password correct?", e.getMessage());
        }
    }

    /**
     * Test a to open a keystore then remove its backing File (and replace it
     * with a directory with the same name) and try to write in to disk :
     * will throw an UnableToSaveKeystore
     */
    @Test
    public void testDeleteThenWrite() throws Exception {
        try {
            UpdateCertificates uc = new UpdateCertificates(ksPassword, ksFilename);

            // Replace actual file by a directory !
            File keystore = new File(ksFilename);
            keystore.delete();
            keystore.mkdir();

            // Will fail with some IOException
            uc.writeKeyStore();
            fail();
        } catch (UnableToSaveKeystoreException e) {
            assertEquals("There was a problem saving the new Java keystore.", e.getMessage());
        }
    }

    /**
     * Try to send an invalid command ("x") in parseLine : throw UnknownInput
     */
    @Test
    public void testWrongCommand() throws Exception {
        UpdateCertificates uc = new UpdateCertificates(ksPassword, ksFilename);
        try {
            uc.parseLine(INVALID_CACERT);
            fail();
        } catch (UnknownInputException e) {
            assertEquals(INVALID_CACERT, e.getMessage());
        }
    }

    /**
     * Test to insert a valid certificate and then check if it's really in KS.
     */
    @Test
    public void testAdd() throws Exception {
        UpdateCertificates uc = new UpdateCertificates(ksPassword, ksFilename);
        uc.parseLine(ADD_CACERT);
        uc.writeKeyStore();

        assertEquals(true, uc.contains(ALIAS_CACERT));
    }

    /**
     * Test to insert a invalide certificate : no exception, but check there
     * is no alias created with that name
     */
    @Test
    public void testAddInvalidCert() throws Exception {
        UpdateCertificates uc = new UpdateCertificates(ksPassword, ksFilename);
        uc.parseLine("+/usr/share/ca-certificates/null.crt");
        uc.writeKeyStore();

        assertEquals(false, uc.contains("debian:null.crt"));
    }

    /**
     * Try to add same certificate multiple time : we replace it and
     * there is only one alias.
     */
    @Test
    public void testReplace() throws Exception {
        UpdateCertificates uc = new UpdateCertificates(ksPassword, ksFilename);
        uc.parseLine(ADD_CACERT);
        uc.parseLine(ADD_CACERT);
        uc.writeKeyStore();

        assertEquals(true, uc.contains(ALIAS_CACERT));
    }

    /**
     * Try to remove a non-existant certificate : it's a no-op.
     */
    @Test
    public void testRemove() throws Exception {
        UpdateCertificates uc = new UpdateCertificates(ksPassword, ksFilename);
        uc.parseLine(REMOVE_CACERT);
        uc.writeKeyStore();

        // We start with empty KS, so it shouldn't do anything
        assertEquals(false, uc.contains(ALIAS_CACERT));
    }

    /**
     * Try to add cert, write to disk, then open keystore again and remove.
     */
    @Test
    public void testAddThenRemove() throws Exception {
        UpdateCertificates ucAdd = new UpdateCertificates(ksPassword, ksFilename);
        ucAdd.parseLine(ADD_CACERT);
        ucAdd.writeKeyStore();

        assertEquals(true, ucAdd.contains(ALIAS_CACERT));

        UpdateCertificates ucRemove = new UpdateCertificates(ksPassword, ksFilename);
        ucRemove.parseLine(REMOVE_CACERT);
        ucRemove.writeKeyStore();

        assertEquals(false, ucRemove.contains(ALIAS_CACERT));
    }

}
