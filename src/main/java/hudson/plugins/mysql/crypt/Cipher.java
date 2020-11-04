/**
 * The person or persons who have associated work with this document (the
 * "Dedicator" or "Certifier") hereby either (a) certifies that, to the best of
 * his knowledge, the work of authorship identified is in the public domain of
 * the country from which the work is published, or (b) hereby dedicates
 * whatever copyright the dedicators holds in the work of authorship identified
 * below (the "Work") to the public domain. A certifier, moreover, dedicates any
 * copyright interest he may have in the associated work, and for these
 * purposes, is described as a "dedicator" below.
 *
 * A certifier has taken reasonable steps to verify the copyright status of this
 * work. Certifier recognizes that his good faith efforts may not shield him
 * from liability if in fact the work certified is not in the public domain.
 *
 * Dedicator makes this dedication for the benefit of the public at large and to
 * the detriment of the Dedicator's heirs and successors. Dedicator intends this
 * dedication to be an overt act of relinquishment in perpetuity of all present
 * and future rights under copyright law, whether vested or contingent, in the
 * Work. Dedicator understands that such relinquishment of all rights includes
 * the relinquishment of all rights to enforce (by lawsuit or otherwise) those
 * copyrights in the Work.
 *
 * Dedicator recognizes that, once placed in the public domain, the Work may be
 * freely reproduced, distributed, transmitted, used, modified, built upon, or
 * otherwise exploited by anyone for any purpose, commercial or non-commercial,
 * and in any way, including by methods that have not yet been invented or
 * conceived.
 */
package hudson.plugins.mysql.crypt;

import at.favre.lib.crypto.bcrypt.BCrypt;
import hudson.plugins.mysql.MySQLSecurityRealm;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

/**
 * This class produces an encrypted string based upon the selected cipher or
 * digest method.
 *
 * @author Alex Ackerman
 */
public class Cipher
{
    /**
     * Digest algorithm names from the Java Cruptography Architecture Standard
     * Algorithm Name Documentation found at the following address:
     *
     * http://java.sun.com/javase/6/docs/technotes/guides/security/StandardNames.html
     *
     */
    public static final String MD5 = "MD5";
    public static final String SHA1 = "SHA-1";
    public static final String SHA256 = "SHA-256";
    public static final String SHA384 = "SHA-384";
    public static final String SHA512 = "SHA-512";
    public static final String CRYPT = "Crypt";
    public static final String BCRYPT = "BCrypt";

    public Cipher(String type)
    {
        this.encryptionMethod = type;
        salt = null;
    }

    public Cipher(String type, String salt)
    {
        this.encryptionMethod = type;
        this.salt = salt;
    }

    public String encode(String plaintext) throws EncryptionException
    {
        if ( plaintext == null ) return null;
        if ((salt != null) || encryptionMethod.equals(this.CRYPT))
        {
            return JCrypt.crypt(salt, plaintext);
        }
        else
        {
            try
            {
                MessageDigest md = MessageDigest.getInstance(encryptionMethod);
                md.reset();
                byte[] textBytes = plaintext.getBytes();
                md.update(textBytes);
                byte[] mdp = md.digest();
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < mdp.length; ++i) {
                    sb.append(String.format("%02x", mdp[i]));
                }
                return sb.toString();
            }
            catch (NoSuchAlgorithmException ex)
            {
                throw new EncryptionException();
            }
        }
    }

    public boolean checkPassword(String password, String storedPassword) throws EncryptionException
    {
        if ( encryptionMethod.equals(this.BCRYPT))
        {
            BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), storedPassword);
            return result.verified == true;
        }
        else
        {
            String encryptedPassword = encode(password.trim());
            LOGGER.fine("Encrypted Password: " + encryptedPassword);
            LOGGER.fine("Stored Password: " + storedPassword);
            return storedPassword.equals(encryptedPassword);
        }
    }

    private String encryptionMethod;
    private String salt;

    /**
     * Logger for debugging purposes.
     */
    private static final Logger LOGGER =
            Logger.getLogger(Cipher.class.getName());
}
