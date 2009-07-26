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

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.logging.Logger;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.dao.DataAccessException;

/**
 * Implementation of the AbstractPasswordBasedSecurityRealm that uses a MySQL
 * database as the source of authentication information.
 * 
 * @author Alex Ackerman
 */
public class MySQLSecurityRealm extends AbstractPasswordBasedSecurityRealm
{

    @DataBoundConstructor
    public MySQLSecurityRealm(String myServer, String myUsername, String myPassword,
            String myPort, String myDatabase, String myDataTable, String myUserField,
            String myPassField, String myCondition)
    {
        this.myServer = Util.fixEmptyAndTrim(myServer);
        this.myUsername = Util.fixEmptyAndTrim(myUsername);
        this.myPassword = Util.fixEmptyAndTrim(myPassword);
        this.myPort = Util.fixEmptyAndTrim(myPort);
        if ((myPort == null) || (myPort.equals("")))
            myPort = "3306";
        this.myPort = myPort;
        this.myDatabase = Util.fixEmptyAndTrim(myDatabase);
        this.myCondition = Util.fixEmptyAndTrim(myCondition);
        this.myDataTable = Util.fixEmptyAndTrim(myDataTable);
        this.myUserField = Util.fixEmptyAndTrim(myUserField);
        this.myPassField = Util.fixEmptyAndTrim(myPassField);
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
        LOGGER.fine("MySQLSecurity: Connection String - " + connectionString);
        Connection conn = null;
        try
        {
            // Connect to the database
            Class.forName("com.mysql.jdbc.Driver").newInstance();
            conn = DriverManager.getConnection(connectionString,
                    myUsername, myPassword);
            LOGGER.info("MySQLSecurity: Connection established.");

            // Prepare the statement and query the user table
            // TODO: Review userQuery to see if there's a better way to do this
            String userQuery = "SELECT * FROM " + myDataTable + " WHERE " +
                    myUserField + " = ?";
            PreparedStatement statement = conn.prepareStatement(userQuery);
            statement.setString(1, myDataTable);
            LOGGER.fine("MySQLSecurity: Query Info - ");
            LOGGER.fine("- Table: " + myDataTable);
            LOGGER.fine("- User Field: " + myUserField);
            LOGGER.fine("- Username: " + myUsername);
            //statement.setString(2, myUserField);
            statement.setString(1, username);
            ResultSet results = statement.executeQuery();
            LOGGER.fine("MySQLSecurity: Query executed.");

            // Compare the provided password with the stored one
            if (results.first())
            {
                String storedPassword = results.getString(myPassField);
                MessageDigest md = MessageDigest.getInstance(this.MD5);
                md.reset();
                byte[] passBytes = password.getBytes();
                md.update(passBytes);
                //String encryptedPassword = md.toString();
                String encryptedPassword = password;
                if (!storedPassword.equals(encryptedPassword))
                {
                    LOGGER.warning("MySQLSecurity: Invalid Username or Password");
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
                LOGGER.warning("MySQLSecurity: Invalid Username or Password");
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
                    LOGGER.info("MySQLSecurity: Connection closed.");
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
        UserDetails user = null;
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
            // TODO: Review userQuery to see if there's a better way to do this
            String userQuery = "SELECT * FROM " + myDataTable + " WHERE " +
                    myUserField + " = ?";
            PreparedStatement statement = conn.prepareStatement(userQuery);
            //statement.setString(1, myDataTable);
            //statement.setString(2, myUserField);
            statement.setString(1, username);
            ResultSet results = statement.executeQuery();
            LOGGER.fine("MySQLSecurity: Query executed.");

            // Grab the first result (should be only user returned)
            if (results.first())
            {
                // Build the user detail
                user = new MySQLUserDetail(username, "",
                            true, true, true, true, null);
            }
            else
            {
                LOGGER.warning("MySQLSecurity: Invalid Username or Password");
                throw new UsernameNotFoundException("MySQL: User not found");
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
                    LOGGER.info("MySQLSecurity: Connection closed.");
                }
                catch (Exception ex)
                {
                    /** Ignore any errors **/
                }
            }
        }
        return user;
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
        throw new UsernameNotFoundException("Non-supported function");
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
