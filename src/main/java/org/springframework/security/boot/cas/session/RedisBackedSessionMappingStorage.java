/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
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

import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpSession;

import org.jasig.cas.client.session.SessionMappingStorage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;

/**
 * For Session Storage With Redis
 * https://www.cnblogs.com/huangbin/p/3282643.html
 */
public final class RedisBackedSessionMappingStorage implements SessionMappingStorage {

	private final Logger log = LoggerFactory.getLogger(getClass());
	private static final int TIMEOUT = 60 * 60 * 24;
	private static final String MANAGED_SESSIONS = "MANAGED_SESSIONS.";
	private static final String ID_TO_SESSION_KEY_MAPPING = "ID_TO_SESSION_KEY_MAPPING.";
	private RedisTemplate<String, Object> redisTemplate;

	public RedisBackedSessionMappingStorage(RedisTemplate<String, Object> redisTemplate) {
		this.redisTemplate = redisTemplate;
	}

	@Override
	public synchronized void addSessionById(String mappingId, HttpSession session) {
		try {

			redisTemplate.opsForValue().set(ID_TO_SESSION_KEY_MAPPING + session.getId(), mappingId, TIMEOUT, TimeUnit.SECONDS);
			redisTemplate.opsForValue().set(MANAGED_SESSIONS + mappingId, session, TIMEOUT, TimeUnit.SECONDS);

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

			final Object mappingId = redisTemplate.opsForValue().get(ID_TO_SESSION_KEY_MAPPING + sessionId);

			if (log.isDebugEnabled()) {
				if (mappingId != null) {
					log.debug("Found mapping for session.  Session Removed.");
				} else {
					log.debug("No mapping for session found.  Ignoring.");
				}
			}
			if (mappingId != null) {
				redisTemplate.delete(MANAGED_SESSIONS + mappingId.toString());
			}
			redisTemplate.delete(ID_TO_SESSION_KEY_MAPPING + sessionId);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public synchronized HttpSession removeSessionByMappingId(String mappingId) {
		HttpSession session = null;
		try {

			Object session2 = redisTemplate.opsForValue().get(MANAGED_SESSIONS + mappingId);
			if (log.isDebugEnabled()) {
				if (session2 != null) {
					log.debug("Found mapping for session.  Session Removed.");
				} else {
					log.debug("No mapping for session found.  Ignoring.");
				}
			}
			session = (HttpSession) session2;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

		if (session != null) {
			removeBySessionById(session.getId());
		}

		return session;
	}
}
