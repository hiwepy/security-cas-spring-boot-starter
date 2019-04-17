/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.cas.session;

import javax.servlet.http.HttpSession;

import org.jasig.cas.client.session.SessionMappingStorage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.rubyeye.xmemcached.XMemcachedClient;

/**
 * For Session Storage With Memcached
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public final class MemcachedBackedSessionMappingStorage implements SessionMappingStorage {

	private final Logger log = LoggerFactory.getLogger(getClass());
	private static final int TIMEOUT = 60 * 60 * 24;
	private static final String MANAGED_SESSIONS = "MANAGED_SESSIONS.";
	private static final String ID_TO_SESSION_KEY_MAPPING = "ID_TO_SESSION_KEY_MAPPING.";
	private XMemcachedClient client;

	public MemcachedBackedSessionMappingStorage(XMemcachedClient client) {
		this.client = client;
	}

	@Override
	public synchronized void addSessionById(String mappingId, HttpSession session) {
		try {
			client.set(ID_TO_SESSION_KEY_MAPPING + session.getId(), TIMEOUT, mappingId);
			client.set(MANAGED_SESSIONS + mappingId, TIMEOUT, session);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public synchronized void removeBySessionById(String sessionId) {

		if (log.isDebugEnabled()) {
			log.debug("Attempting to remove Session=[" + sessionId + "]");
		}

		try {
			final String mappingId = client.get(ID_TO_SESSION_KEY_MAPPING + sessionId);
			if (log.isDebugEnabled()) {
				if (mappingId != null) {
					log.debug("Found mapping for session.  Session Removed.");
				} else {
					log.debug("No mapping for session found.  Ignoring.");
				}
			}
			client.delete(MANAGED_SESSIONS + mappingId);
			client.delete(ID_TO_SESSION_KEY_MAPPING + sessionId);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public synchronized HttpSession removeSessionByMappingId(String mappingId) {
		HttpSession session = null;
		try {

			Object session2 = client.get(MANAGED_SESSIONS + mappingId);
			if (session2 != null) {
				session = (HttpSession) session2;
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

		if (session != null) {
			removeBySessionById(session.getId());
		}

		return session;
	}
}