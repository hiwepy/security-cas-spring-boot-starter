package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(SecurityCasProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityCasProperties {


	public static final String PREFIX = "spring.security.cas";

	/** Whether Enable Cas. */
	private boolean enabled = false;
	
}
