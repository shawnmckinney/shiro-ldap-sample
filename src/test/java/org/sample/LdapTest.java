package org.sample;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;

public class LdapTest
{

    public static final String userName = "uid=foofighters,ou=People,dc=example,dc=com";
    public static final String password = "password";

    public static void main(String[] args)
    {
        Factory<SecurityManager> factory = new IniSecurityManagerFactory( "classpath:shiro.ini" );
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager( securityManager );

        UsernamePasswordToken token = new UsernamePasswordToken( userName, password );
        Subject currentUser = SecurityUtils.getSubject();

        try
        {
            currentUser.login( token );
            System.out.println( "We've authenticated! :)" );
        }
        catch ( AuthenticationException e )
        {
            System.out.println( "We did not authenticate :(" );
            e.printStackTrace();
        }

        if ( currentUser.hasRole( "role" ) )
        {
            System.out.println( "We have the role! :)" );
        }
        else
        {
            System.out.println( "We do not have the role :(" );
        }
        if ( currentUser.isPermitted( "foo.blah" ) )
        {
            System.out.println( "We're authorized! :)" );
        }
        else
        {
            System.out.println( "We are not authorized :(" );
        }
    }
}