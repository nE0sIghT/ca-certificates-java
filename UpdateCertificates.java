/*
 * Copyright (C) 2011 Torsten Werner <twerner@debian.org>
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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

/**
 * This code is a re-implementation of the idea from Ludwig Nussel found in
 * http://gitorious.org/opensuse/ca-certificates/blobs/master/keystore.java
 * for the Debian operating system. It updates the global JVM keystore.
 * 
 * @author Torsten Werner
 * @author Damien Raude-Morvan
 */
public class UpdateCertificates {
	
    private char[] password = null;
    
    private String ksFilename = null;
    
    private KeyStore ks = null;
    
    private CertificateFactory certFactory = null;
    
    public static void main(String[] args) throws IOException, GeneralSecurityException {
        String passwordString = "changeit";
        if (args.length == 2 && args[0].equals("-storepass")) {
            passwordString = args[1];
        }
        else if (args.length > 0) {
            System.err.println("Usage: java UpdateCertificates [-storepass <password>]");
            System.exit(1);
        }

		try {
			UpdateCertificates uc = new UpdateCertificates(passwordString, "/etc/ssl/certs/java/cacerts");
	        // Force reading of inputstream in UTF-8
	        uc.processChanges(new InputStreamReader(System.in, "UTF8"));
	        uc.writeKeyStore();
		} catch (Exceptions.InvalidKeystorePassword e) {
			e.printStackTrace(System.err);
			System.exit(1);
		} catch (Exceptions.UnableToSaveKeystore e) {
			e.printStackTrace(System.err);
			System.exit(1);
		}
    }
    
    public UpdateCertificates(final String passwordString, final String keystoreFile) throws IOException, GeneralSecurityException, Exceptions.InvalidKeystorePassword {
        this.password = passwordString.toCharArray();
        this.ksFilename = keystoreFile;
        this.ks = openKeyStore();
        this.certFactory = CertificateFactory.getInstance("X.509");
	}

    /**
     * Try to open a existing keystore or create an new one.
     */
    private KeyStore openKeyStore() throws GeneralSecurityException, IOException, Exceptions.InvalidKeystorePassword {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        File certInputFile = new File(this.ksFilename);
        FileInputStream certInputStream = null;
        if (certInputFile.canRead()) {
            certInputStream = new FileInputStream(certInputFile);
        }
        try {
            ks.load(certInputStream, this.password);
        }
        catch (IOException e) {
            throw new Exceptions.InvalidKeystorePassword("Cannot open Java keystore. Is the password correct?", e);
        }
        if (certInputStream != null) {
            certInputStream.close();
        }
        return ks;
    }
    
    /**
     * Until reader EOF, try to read changes and send each to {@link #parseLine(String)}.
     */
    protected void processChanges(final Reader reader)
            throws IOException, GeneralSecurityException {
        String line;
        BufferedReader bufferedStdinReader = new BufferedReader(reader);
        while((line = bufferedStdinReader.readLine()) != null) {
        	try {
        		parseLine(line);
        	} catch (Exceptions.UnknownInput e) {
        		System.err.println("Unknown input: " + line);
        		// Keep processing for others lines
        	}
        }
    }
    
    /**
     * Parse given line to choose between {@link #addAlias(String, Certificate)}
     * or {@link #deleteAlias(String)}.
     */
    protected void parseLine(final String line)
            throws GeneralSecurityException, IOException, Exceptions.UnknownInput {
    	assert this.ks != null;
    	
        String path = line.substring(1);
        String filename = path.substring(path.lastIndexOf("/") + 1);
        String alias = "debian:" + filename;
        if(line.startsWith("+")) {
            Certificate cert = loadCertificate(path);
            if (cert == null) {
                return;
            }
            addAlias(alias, cert);
        }
        else if (line.startsWith("-")) {
            deleteAlias(alias);
            // Remove old non-prefixed aliases, too. This code should be
            // removed after the release of Wheezy.
            deleteAlias(filename);
        }
        else {
        	throw new Exceptions.UnknownInput(line);
        }        
    }
    
    /**
     * Delete cert in keystore at given alias.
     */
    private void deleteAlias(final String alias) throws GeneralSecurityException {
    	assert this.ks != null;
    	
        if (contains(alias)) {
            System.out.println("Removing " + alias);
            this.ks.deleteEntry(alias);
        }
    }

    /**
     * Add or replace existing cert in keystore with given alias.
     */
	private void addAlias(final String alias, final Certificate cert)
			throws KeyStoreException {
		assert this.ks != null;
		
		if(contains(alias)) {
		    System.out.println("Replacing " + alias);
		    this.ks.deleteEntry(alias);
		}
		else {
		    System.out.println("Adding " + alias);
		}
		this.ks.setCertificateEntry(alias, cert);
	}

	/**
	 * Returns true when alias exist in keystore.
	 */
	protected boolean contains(String alias) throws KeyStoreException {
		assert this.ks != null;
		
		return this.ks.containsAlias(alias);
	}

	/**
	 * Try to load a certificate instance from given path.
	 */
    private Certificate loadCertificate(final String path) {
    	assert this.certFactory != null;
    	
        Certificate cert = null;
        try {
            FileInputStream certFile = new FileInputStream(path);
            cert = this.certFactory.generateCertificate(certFile);
            certFile.close();
        }
        catch (Exception e) {
            System.err.println("Warning: there was a problem reading the certificate file " +
                path + ". Message:\n  " + e.getMessage());
        }
        return cert;
    }
    
    /**
     * Write actual keystore content to disk.
     */
    protected void writeKeyStore() throws GeneralSecurityException, Exceptions.UnableToSaveKeystore {
    	assert this.ks != null;
    	
        try {
            FileOutputStream certOutputFile = new FileOutputStream(this.ksFilename);
            this.ks.store(certOutputFile, this.password);
            certOutputFile.close();
        }
        catch (IOException e) {
        	throw new Exceptions.UnableToSaveKeystore("There was a problem saving the new Java keystore.", e);
        }
    }
}
