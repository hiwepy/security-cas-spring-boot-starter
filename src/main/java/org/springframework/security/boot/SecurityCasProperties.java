package org.springframework.security.boot;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(SecurityCasProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityCasProperties {


	public static final String PREFIX = "spring.security.cas";

	/** Whether Enable Cas. */
	private boolean enabled = false;
	
}
