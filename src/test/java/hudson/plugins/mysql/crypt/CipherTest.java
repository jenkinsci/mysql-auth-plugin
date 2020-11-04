package hudson.plugins.mysql.crypt;

import java.util.Collections;

import junit.framework.TestCase;

import org.junit.Assert;
import org.junit.Test;
import org.jvnet.hudson.test.HudsonTestCase;

public class CipherTest extends HudsonTestCase {

	@Test
	public void testSHACipher() throws Exception {
        Cipher c = new Cipher("SHA-1");
		String cipheredPassword = c.encode("test");
		assertEquals("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", cipheredPassword);
	}

	@Test
	public void testBCryptCipher() throws Exception {
		Cipher c = new Cipher("BCrypt");
		String[] cipheredPasswords = {"$2y$10$n0/WvVLImr7LZPUpkliOleLACccBpegr2VliPH1Vc6OUYJU31Ow.m", "$2y$10$K6NTfLtIIyKuyqB5/PYUAuT8dtj.Ka.UIc.VFZVobW6e2bTAn8xES"};
		for( String cipheredPassword: cipheredPasswords )
		{
			assertTrue(c.checkPassword("test", cipheredPassword));
			assertFalse(c.checkPassword("not-test", cipheredPassword));
		}
	}
}