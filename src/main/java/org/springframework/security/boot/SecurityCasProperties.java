package org.springframework.security.boot;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * SecurityCasProperties.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@ConfigurationProperties(SecurityCasProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityCasProperties {


	public static final String PREFIX = "spring.security.cas";

	/** Whether Enable Cas. */
	private boolean enabled = false;
	
}
