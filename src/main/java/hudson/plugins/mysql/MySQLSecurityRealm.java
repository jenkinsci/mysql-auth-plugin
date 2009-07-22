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
package hudson.plugins.mysql;

import groovy.lang.Binding;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.util.spring.BeanBuilder;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.logging.Logger;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.web.context.WebApplicationContext;

/**
 * Implementation of the AbstractPasswordBasedSecurityRealm that uses a MySQL
 * database as the source of authentication information.
 * 
 * @author Alex Ackerman
 */
public class MySQLSecurityRealm extends AbstractPasswordBasedSecurityRealm
{

    @DataBoundConstructor
    public MySQLSecurityRealm(String server, String username, String password,
            String port, String database, String table, String userField,
            String passField, String condition)
    {
        myServer = Util.fixEmptyAndTrim(server);
        myUsername = Util.fixEmptyAndTrim(username);
        myPassword = Util.fixEmptyAndTrim(password);
        port = Util.fixEmptyAndTrim(port);
        if (port == null)
            port = "3306";
        myPort = port;
        myDatabase = Util.fixEmptyAndTrim(database);
        myCondition = Util.fixEmptyAndTrim(condition);
        myDataTable = Util.fixEmptyAndTrim(table);
        myUserField = Util.fixEmptyAndTrim(userField);
        myPassField = Util.fixEmptyAndTrim(passField);
    }

    @Override
    public SecurityComponents createSecurityComponents()
    {
        Binding binding = new Binding();
        binding.setVariable("mysqlAuth", new Authenticator());
        binding.setVariable("instance", this);
        BeanBuilder builder = new BeanBuilder(getClass().getClassLoader());
        builder.parse(getClass().getResourceAsStream("MySQL.groovy"), binding);
        WebApplicationContext context = builder.createApplicationContext();
        return new SecurityComponents(
            findBean(AuthenticationManager.class, context), this);
    }

    public static final class DescriptorImpl extends Descriptor<SecurityRealm>
    {
        public String getHelpFile() {
            return "/plugin/hudson-mysql/help/overview.html";
        }
        
        @Override
        public String getDisplayName() {
            return "MySQL";
        }
    }

    @Extension
    public static DescriptorImpl install()
    {
        return new DescriptorImpl();
    }

    /**
     * Authenticates the specified user using the password against the stored
     * database configuration.
     *
     * @param username      The username to lookup
     * @param password      The password to use for authentication
     * @return              A UserDetails object containing information about
     *                      the user.
     * @throws AuthenticationException  Thrown when the username/password do
     *                                  not match stored values.
     */
    @Override
    protected UserDetails authenticate(String username, String password)
            throws AuthenticationException
    {
        UserDetails userDetails = null;

        String connectionString;

        connectionString = "jdbc:mysql://" + myServer + "/" +
                myDatabase;
        LOGGER.info("MySQLSecurity: Connection String - " + connectionString);
        Connection conn = null;
        try
        {
            // Connect to the database
            Class.forName("com.mysql.jdbc.Driver").newInstance();
            conn = DriverManager.getConnection(connectionString,
                    myUsername, myPassword);
            LOGGER.info("MySQLSecurity: Connection established.");

            // Prepare the statement and query the user table
            String userQuery = "SELECT * FROM ? WHERE ? = ?";
            PreparedStatement statement = conn.prepareStatement(userQuery);
            // TODO: Find a way to get the info from the configuration page here
            statement.setString(1, myDataTable);
            statement.setString(2, myUserField);
            statement.setString(3, username);
            ResultSet results = statement.executeQuery();
            LOGGER.info("MySQLSecurity: Query executed.");

            // Compare the provided password with the stored one
            if (results.first())
            {
                String storedPassword = results.getString(myPassField);
                MessageDigest md = MessageDigest.getInstance(this.MD5);
                md.reset();
                byte[] passBytes = password.getBytes();
                md.update(passBytes);
                String encryptedPassword = md.toString();
                if (!storedPassword.equals(encryptedPassword))
                {
                    LOGGER.info("MySQLSecurity: Invalid Username or Password");
                    throw new MySQLAuthenticationException("Invalid Username or Password");
                }
                else
                {
                    // Password is valid.  Build UserDetail
                    userDetails = new MySQLUserDetail(username, encryptedPassword,
                            true, true, true, true, null);
                }
            }
            else
            {
                LOGGER.info("MySQLSecurity: Invalid Username or Password");
                throw new MySQLAuthenticationException("Invalid Username or Password");
            }

        }
        catch (Exception e)
        {
            LOGGER.warning("MySQLSecurity Realm Error: " + e.getLocalizedMessage());
        }
        finally
        {
            if (conn != null)
            {
                try
                {
                    conn.close();
                    LOGGER.info("MySQL Connection closed.");
                }
                catch (Exception ex)
                {
                    /** Ignore any errors **/
                }
            }
        }

        return userDetails;
    }

    /**
     *
     * @param username
     * @return
     * @throws UsernameNotFoundException
     * @throws DataAccessException
     */
    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException, DataAccessException
    {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     *
     * @param groupname
     * @return
     * @throws UsernameNotFoundException
     * @throws DataAccessException
     */
    @Override
    public GroupDetails loadGroupByGroupname(String groupname)
            throws UsernameNotFoundException, DataAccessException
    {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    class Authenticator extends AbstractUserDetailsAuthenticationProvider
    {

        @Override
        protected void additionalAuthenticationChecks(UserDetails userDetails,
                UsernamePasswordAuthenticationToken authentication)
                throws AuthenticationException {
            // Assumed to be done in the retrieveUser method
        }

        @Override
        protected UserDetails retrieveUser(String username,
                UsernamePasswordAuthenticationToken authentication)
                throws AuthenticationException {
            return MySQLSecurityRealm.this.authenticate(username,
                    authentication.getCredentials().toString());
        }

    }

    /**
     * Logger for debugging purposes.
     */
    private static final Logger LOGGER =
            Logger.getLogger(MySQLSecurityRealm.class.getName());

    /**
     * The MySQL server to use.
     */
    private String myServer;
    /**
     * The MySQL username to use to connect to the database server.
     */
    private String myUsername;
    /**
     * The MySQL password to use to connect to the database server.
     */
    private String myPassword;
    /**
     * The database containing the user's authentication information.
     */
    private String myDatabase;
    /**
     * The table containing a user's authentication information.
     */
    private String myDataTable;
    /**
     * Username field in the database.
     */
    private String myUserField;
    /**
     * Password field in the database.
     */
    private String myPassField;
    /**
     * Port used by the MySQL server.  If not specified, defaults to 3306.
     */
    private String myPort;
    /**
     * Condition string which may prevent user from being enabled.  This is a
     * field used by Bugzilla.
     */
    private String myCondition;

    /**
     * Digest algorithm names from the Java Cruptography Architecture Standard
     * Algorithm Name Documentation found at the following address:
     * 
     * http://java.sun.com/javase/6/docs/technotes/guides/security/StandardNames.html
     * 
     */
    private static final String MD5 = "MD5";
    private static final String SHA1 = "SHA-1";
    private static final String SHA256 = "SHA-256";
    private static final String SHA384 = "SHA-384";
    private static final String SHA512 = "SHA-512";
}
