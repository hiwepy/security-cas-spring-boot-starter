package org.springframework.security.boot.cas.userdetails;

import org.apache.commons.lang3.ArrayUtils;
import org.jasig.cas.client.validation.Assertion;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.cas.userdetails.AbstractCasAssertionUserDetailsService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class GrantedAuthorityFromAssertionAttributesUserDetailsRoutingService extends
        AbstractCasAssertionUserDetailsService {

    private static final String NON_EXISTENT_PASSWORD_VALUE = "NO_PASSWORD";

    private SecurityCasAuthcProperties authcProperties;

    public GrantedAuthorityFromAssertionAttributesUserDetailsRoutingService(SecurityCasAuthcProperties authcProperties) {
        this.authcProperties = authcProperties;
    }

    @SuppressWarnings("unchecked")
    @Override
    protected UserDetails loadUserDetails(final Assertion assertion) {
        final List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        HttpServletRequest request = WebUtils.getHttpServletRequest();
        if (Objects.nonNull(request)) {

            SecurityCasServerProperties serverProperties = authcProperties.getByRequest(request);
            String[] attributes = ArrayUtils.isEmpty(serverProperties.getAttributes()) ? new String[] {} : serverProperties.getAttributes();

            boolean convertToUpperCase = serverProperties.isAttributeConvertToUpperCase();

            for (final String attribute : attributes) {
                final Object value = assertion.getPrincipal().getAttributes().get(attribute);

                if (value == null) {
                    continue;
                }

                if (value instanceof List) {
                    final List list = (List) value;

                    for (final Object o : list) {
                        grantedAuthorities.add(new SimpleGrantedAuthority(
                                convertToUpperCase ? o.toString().toUpperCase() : o
                                        .toString()));
                    }

                }
                else {
                    grantedAuthorities.add(new SimpleGrantedAuthority(
                            convertToUpperCase ? value.toString().toUpperCase() : value
                                    .toString()));
                }

            }
        }


        return new User(assertion.getPrincipal().getName(), NON_EXISTENT_PASSWORD_VALUE,
                true, true, true, true, grantedAuthorities);
    }

}
