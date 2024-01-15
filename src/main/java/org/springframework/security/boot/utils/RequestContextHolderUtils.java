package org.springframework.security.boot.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;

@Slf4j
public class RequestContextHolderUtils {

    public static HttpServletRequest getHttpServletRequest() {
        try {
            RequestAttributes requestAttributes = getRequestAttributesSafely();
            if (requestAttributes != null) {
                return ((ServletRequestAttributes) requestAttributes).getRequest();
            }
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return null;
    }

    public static RequestAttributes getRequestAttributesSafely(){
        RequestAttributes requestAttributes = null;
        try{
            requestAttributes = RequestContextHolder.currentRequestAttributes();
        } catch (IllegalStateException e){

        }
        return requestAttributes;
    }
}
