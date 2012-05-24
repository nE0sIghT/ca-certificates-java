/*
 * Copyright (C) 2011 Torsten Werner <twerner@debian.org>
 * 
 * This code is a re-implementation of the idea from Ludwig Nussel found in
 * http://gitorious.org/opensuse/ca-certificates/blobs/master/keystore.java
 * for the Debian operating system. It updates the global JVM keystore.
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
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public class UpdateCertificates {
    private static char[] password = null;
    private static KeyStore keystore = null;
    private static CertificateFactory certFactory = null;
    
    public static void main(String[] args) throws IOException, GeneralSecurityException {
        String passwordString = "changeit";
        if (args.length == 2 && args[0].equals("-storepass")) {
            passwordString = args[1];
        }
        else if (args.length > 0) {
            System.err.println("Usage: java UpdateCertificates [-storepass <password>]");
            System.exit(1);
        }
        password = passwordString.toCharArray();
        keystore = createKeyStore();
        certFactory = CertificateFactory.getInstance("X.509");
        // Force reading of inputstream int UTF-8
        processChanges(new InputStreamReader(System.in, "UTF8"));
        writeKeyStore();
    }

    private static KeyStore createKeyStore() throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        File certInputFile = new File ("/etc/ssl/certs/java/cacerts");
        FileInputStream certInputStream = null;
        if (certInputFile.canRead()) {
            certInputStream = new FileInputStream(certInputFile);
        }
        try {
            ks.load(certInputStream, password);
        }
        catch (IOException e) {
            System.err.println("Cannot open Java keystore. Is the password correct? Message:\n  " +
                e.getMessage());
            System.exit(1);
        }
        if (certInputStream != null) {
            certInputStream.close();
        }
        return ks;
    }
    
    private static void processChanges(Reader reader)
            throws IOException, GeneralSecurityException {
        String line;
        BufferedReader bufferedStdinReader = new BufferedReader(reader);
        while((line = bufferedStdinReader.readLine()) != null) {
            parseLine(line);
        }
    }
    
    private static void deleteAlias(String alias) throws GeneralSecurityException {
        if (keystore.containsAlias(alias)) {
            System.out.println("Removing " + alias);
            keystore.deleteEntry(alias);
        }
    }
    
    private static void parseLine(String line)
            throws GeneralSecurityException, IOException {
        String path = line.substring(1);
        String filename = path.substring(path.lastIndexOf("/") + 1);
        String alias = "debian:" + filename;
        if(line.startsWith("+")) {
            Certificate cert = createCertificate(path);
            if (cert == null) {
                return;
            }
            if(keystore.containsAlias(alias)) {
                System.out.println("Replacing " + alias);
                keystore.deleteEntry(alias);
            }
            else {
                System.out.println("Adding " + alias);
            }
            keystore.setCertificateEntry(alias, cert);
        }
        else if (line.startsWith("-")) {
            deleteAlias(alias);
            // Remove old non-prefixed aliases, too. This code should be
            // removed after the release of Wheezy.
            deleteAlias(filename);
        }
        else {
            System.err.println("Unknown input: " + line);
        }        
    }

    private static Certificate createCertificate(String path) {
        Certificate cert = null;
        try {
            FileInputStream certFile = new FileInputStream(path);
            cert = certFactory.generateCertificate(certFile);
            certFile.close();
        }
        catch (Exception e) {
            System.err.println("Warning: there was a problem reading the certificate file " +
                path + ". Message:\n  " + e.getMessage());
        }
        return cert;
    }
    
    private static void writeKeyStore() throws GeneralSecurityException {
        try {
            FileOutputStream certOutputFile = new FileOutputStream("/etc/ssl/certs/java/cacerts");
            keystore.store(certOutputFile, password);
            certOutputFile.close();
        }
        catch (IOException e) {
            System.err.println("There was a problem saving the new Java keystore. Message:\n  " +
                e.getMessage());
            System.exit(1);
        }
    }
}
