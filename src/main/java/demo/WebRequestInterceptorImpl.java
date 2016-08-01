package demo;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.UUID;

/**
 * @author Ivan Smorodin
 * @since 01.08.2016
 */
@Component
@Slf4j
public class WebRequestInterceptorImpl implements HandlerInterceptor {

    private RequestMatcher requestMatcher = new AntPathRequestMatcher("/login", "GET", false);
    private RequestMatcher requestMatcherLogin = new AntPathRequestMatcher("/login", "POST", false);

    @Override
    public boolean preHandle(HttpServletRequest req, HttpServletResponse res, Object o) throws Exception {
        SecurityContextImpl securityContext = (SecurityContextImpl) req.getSession().getAttribute("SPRING_SECURITY_CONTEXT");
        final StateResponse state = (StateResponse) req.getSession().getAttribute("state");
        if (state != null) {
            if (securityContext != null) {
                if (!state.getStatus().equals(HttpStatus.OK)) {
                    if (securityContext.getAuthentication().isAuthenticated()) {
                        log.error("auth", securityContext.getAuthentication());
                        securityContext.getAuthentication().setAuthenticated(false);
                        state.setStatus(HttpStatus.PROCESSING);
                        state.setSmsCode("qwerty");
                        res.sendRedirect("/uaa/login");
                    }
                }
            } else if (state.getStatus().equals(HttpStatus.PROCESSING)) {
                log.error("HttpStatus.PROCESSING code = {}", req.getParameter("code"));
            }
        }
        if (containsRegexp(req)) {
            if (state != null && state.getStatus().equals(HttpStatus.PROCESSING)) {
                log.info("state exist =  {} {},{}", state, req, res);
            } else {
                log.info("state not exist =  {},{}", req, res);
                final String newSid = UUID.randomUUID().toString();
                final StateResponse stateResponse = StateResponse.builder().sid(newSid).status(HttpStatus.CREATED).build();
                req.getSession().setAttribute("state", stateResponse);
            }
            log.info("preHandle {},{}", req, res);
        }
        return true;
    }


    private boolean containsRegexp(HttpServletRequest req) {
        return requestMatcher.matches(req) || requestMatcherLogin.matches(req);
    }

    @Override
    public void postHandle(HttpServletRequest req, HttpServletResponse res, Object o, ModelAndView m) throws Exception {
        log.debug("reqqqq {}", req);
        if (containsRegexp(req)) {
            final StateResponse state = (StateResponse) req.getSession().getAttribute("state");
            if (state != null) {
                SecurityContextImpl securityContext = (SecurityContextImpl) req.getSession().getAttribute("SPRING_SECURITY_CONTEXT");
                log.info("postHandle state = {}, {},{}", state, req, res);
                m.addObject("state", state);
//                req.getSession(false).invalidate();
            }
        }
    }

    @Override
    public void afterCompletion(HttpServletRequest req, HttpServletResponse res, Object o, Exception e) throws Exception {
        log.info("afterCompletion {},{}", req, res);
    }
}
