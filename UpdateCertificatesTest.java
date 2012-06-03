/*
 * Copyright (C) 2012 Damien Raude-Morvan <drazzib@debian.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;

/**
 * Tests for {@link UpdateCertificates}.
 * 
 * @author Damien Raude-Morvan
 */
public class UpdateCertificatesTest {

	private static final String ALIAS_CACERT = "debian:cacert.org.crt";
	private static final String INVALID_CACERT = "x/usr/share/ca-certificates/cacert.org/cacert.org.crt";
	private static final String REMOVE_CACERT = "-/usr/share/ca-certificates/cacert.org/cacert.org.crt";
	private static final String ADD_CACERT = "+/usr/share/ca-certificates/cacert.org/cacert.org.crt";

	private String ksFilename = null;
	private String ksPassword = null;

	@Before
	public void start() {
		this.ksFilename = "./tests-cacerts";
		this.ksPassword = "changeit";
		// Delete any previous file
		File keystore = new File(this.ksFilename);
		keystore.delete();
	}

	/**
	 * Test a simple open then write without any modification.
	 */
	@Test
	public void testNoop() throws IOException, GeneralSecurityException,
			Exceptions.InvalidKeystorePassword, Exceptions.UnableToSaveKeystore {
		UpdateCertificates uc = new UpdateCertificates(this.ksPassword,
				this.ksFilename);
		uc.writeKeyStore();
	}

	/**
	 * Test a to open a keystore and write without any modification
	 * and then try to open it again with wrong password : will throw a
	 * InvalidKeystorePassword
	 */
	@Test
	public void testWriteThenOpenWrongPwd() throws IOException,
			GeneralSecurityException, Exceptions.UnableToSaveKeystore {
		try {
			UpdateCertificates uc = new UpdateCertificates(this.ksPassword,
					this.ksFilename);
			uc.writeKeyStore();
		} catch (Exceptions.InvalidKeystorePassword e) {
			Assert.fail();
		}

		try {
			UpdateCertificates uc = new UpdateCertificates("wrongpassword",
					this.ksFilename);
			Assert.fail();
			uc.writeKeyStore();
		} catch (Exceptions.InvalidKeystorePassword e) {
			Assert.assertEquals(
					"Cannot open Java keystore. Is the password correct?",
					e.getMessage());
		}
	}

	/**
	 * Test a to open a keystore then remove its backing File (and replace it
	 * with a directory with the same name) and try to write in to disk :
	 * will throw an UnableToSaveKeystore
	 */
	@Test
	public void testDeleteThenWrite() throws IOException,
			GeneralSecurityException, Exceptions.InvalidKeystorePassword {
		try {
			UpdateCertificates uc = new UpdateCertificates(this.ksPassword,
					this.ksFilename);

			// Replace actual file by a directory !
			File keystore = new File(this.ksFilename);
			keystore.delete();
			keystore.mkdir();

			// Will fail with some IOException
			uc.writeKeyStore();
			Assert.fail();
		} catch (Exceptions.UnableToSaveKeystore e) {
			Assert.assertEquals(
					"There was a problem saving the new Java keystore.",
					e.getMessage());
		}
	}

	/**
	 * Try to send an invalid command ("x") in parseLine : throw UnknownInput
	 */
	@Test
	public void testWrongCommand() throws IOException,
			GeneralSecurityException, Exceptions.InvalidKeystorePassword {
		UpdateCertificates uc = new UpdateCertificates(this.ksPassword,
				this.ksFilename);
		try {
			uc.parseLine(INVALID_CACERT);
			Assert.fail();
		} catch (Exceptions.UnknownInput e) {
			Assert.assertEquals(INVALID_CACERT, e.getMessage());
		}
	}

	/**
	 * Test to insert a valid certificate and then check if it's really in KS.
	 */
	@Test
	public void testAdd() throws IOException, GeneralSecurityException,
			Exceptions.UnknownInput, Exceptions.InvalidKeystorePassword,
			Exceptions.UnableToSaveKeystore {
		UpdateCertificates uc = new UpdateCertificates(this.ksPassword,
				this.ksFilename);
		uc.parseLine(ADD_CACERT);
		uc.writeKeyStore();

		Assert.assertEquals(true, uc.contains(ALIAS_CACERT));
	}

	/**
	 * Test to insert a invalide certificate : no exception, but check there
	 * is no alias created with that name
	 */
	@Test
	public void testAddInvalidCert() throws IOException,
			GeneralSecurityException, Exceptions.UnknownInput,
			Exceptions.InvalidKeystorePassword, Exceptions.UnableToSaveKeystore {
		UpdateCertificates uc = new UpdateCertificates(this.ksPassword,
				this.ksFilename);
		uc.parseLine("+/usr/share/ca-certificates/null.crt");
		uc.writeKeyStore();

		Assert.assertEquals(false, uc.contains("debian:null.crt"));
	}

	/**
	 * Try to add same certificate multiple time : we replace it and
	 * there is only one alias.
	 */
	@Test
	public void testReplace() throws IOException, GeneralSecurityException,
			Exceptions.UnknownInput, Exceptions.InvalidKeystorePassword,
			Exceptions.UnableToSaveKeystore {
		UpdateCertificates uc = new UpdateCertificates(this.ksPassword,
				this.ksFilename);
		uc.parseLine(ADD_CACERT);
		uc.parseLine(ADD_CACERT);
		uc.writeKeyStore();

		Assert.assertEquals(true, uc.contains(ALIAS_CACERT));
	}

	/**
	 * Try to remove a non-existant certificate : it's a no-op.
	 */
	@Test
	public void testRemove() throws IOException, GeneralSecurityException,
			Exceptions.UnknownInput, Exceptions.InvalidKeystorePassword,
			Exceptions.UnableToSaveKeystore {
		UpdateCertificates uc = new UpdateCertificates(this.ksPassword,
				this.ksFilename);
		uc.parseLine(REMOVE_CACERT);
		uc.writeKeyStore();

		// We start with empty KS, so it shouldn't do anything
		Assert.assertEquals(false, uc.contains(ALIAS_CACERT));
	}

	/**
	 * Try to add cert, write to disk, then open keystore again and remove.
	 */
	@Test
	public void testAddThenRemove() throws IOException,
			GeneralSecurityException, Exceptions.UnknownInput,
			Exceptions.InvalidKeystorePassword, Exceptions.UnableToSaveKeystore {
		UpdateCertificates ucAdd = new UpdateCertificates(this.ksPassword,
				this.ksFilename);
		ucAdd.parseLine(ADD_CACERT);
		ucAdd.writeKeyStore();

		Assert.assertEquals(true, ucAdd.contains(ALIAS_CACERT));

		UpdateCertificates ucRemove = new UpdateCertificates(this.ksPassword,
				this.ksFilename);
		ucRemove.parseLine(REMOVE_CACERT);
		ucRemove.writeKeyStore();

		Assert.assertEquals(false, ucRemove.contains(ALIAS_CACERT));
	}

}
