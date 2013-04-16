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
}