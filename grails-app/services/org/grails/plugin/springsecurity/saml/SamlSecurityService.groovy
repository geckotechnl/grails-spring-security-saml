package org.grails.plugin.springsecurity.saml

import grails.plugin.springsecurity.SpringSecurityService
import groovy.util.logging.Slf4j

/**
 * A subclass of {@link SpringSecurityService} to replace {@link getCurrentUser()}
 * method. The parent implementation performs a database load, but we do not have
 * database users here, so we simply return the authentication details.
 *
 * @author alvaro.sanchez
 */
@Slf4j('logger')
class SamlSecurityService extends SpringSecurityService {
    SpringSamlUserDetailsService userDetailsService

    def userCache
    static transactional = false
    def config

    SpringSamlUserDetailsService getUserDetailsService() {
        return userDetailsService
    }

    void setUserDetailsService(SpringSamlUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService
    }

    Object getCurrentUser() {
        logger.debug("SamlSecurityService getCurrentUser")
        def userDetails
        if (!isLoggedIn()) {
            userDetails = null
        } else {
            userDetails = getAuthentication().details

            if(!userDetails) {
                def principal = getPrincipal()
                userDetails = getCurrentPersistedUser(principal?.username)
            } else {
                if (config?.saml.autoCreate.active) {
                    String userKey = config?.saml.autoCreate.key
                    userDetails = getCurrentPersistedUser(userDetails."$userKey")
                }
            }
        }
        return userDetails
    }

    private Object getCurrentPersistedUser(String username) {
        if (username) {
            String className = config?.userLookup.userDomainClassName
            String userKey = config?.saml.autoCreate.key
            Boolean caseInsensitive = config?.saml?.autoCreate?.caseInsensitiveKey
            if (className && userKey) {
                Class<?> userClass = grailsApplication.getDomainClass(className)?.clazz
                if(caseInsensitive) {
                    return userClass."findBy${userKey.capitalize()}Ilike"(username)
                } else {
                    return userClass."findBy${userKey.capitalize()}"(username)
                }

            }
        } else { return null}
    }

    reactor.bus.Bus sendAndReceive(java.lang.Object obj, groovy.lang.Closure closure) {
        return null
    }
}
