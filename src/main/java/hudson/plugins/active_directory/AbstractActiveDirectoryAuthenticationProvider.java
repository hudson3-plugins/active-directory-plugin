package hudson.plugins.active_directory;

import org.springframework.security.AuthenticationException;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.providers.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.userdetails.UsernameNotFoundException;
import org.springframework.dao.DataAccessException;

/**
 * @author Kohsuke Kawaguchi
 */
public abstract class AbstractActiveDirectoryAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider implements UserDetailsService, GroupDetailsService {
    protected AbstractActiveDirectoryAuthenticationProvider() {
        setHideUserNotFoundExceptions(SHOW_USER_NOT_FOUND_EXCEPTION);
    }

    /**
     * Authenticates the user (if {@code authentication!=null}), or retrieve the user name information (otherwise.)
     */
    protected abstract UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException;

    /**
     * Returns true if we can retrieve user just from the name without supplying any credential.
     */
    protected abstract boolean canRetrieveUserByName();

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
        return retrieveUser(username,null);
    }

    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        // active directory authentication is not by comparing clear text password,
        // so there's nothing to do here.
    }

    /**
     * Setting this to true might help with diagnosing login problem.
     */
    public static boolean SHOW_USER_NOT_FOUND_EXCEPTION = Boolean.getBoolean(AbstractActiveDirectoryAuthenticationProvider.class.getName()+".showUserNotFoundException");
}
