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
		String titi = c.encode("toto");
		assertSame("titi", titi);
	}
}