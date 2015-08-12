package org.wso2.carbon.identity.application.authenticator.customauth.internal;

import java.util.Hashtable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.customauth.CustomAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="identity.application.authenticator.customauth.component" immediate="true"
 * @scr.reference name="realm.service"
 * interface="org.wso2.carbon.user.core.service.RealmService"cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class CustomAuthenticatorServiceComponent {

    private static Log log = LogFactory.getLog(CustomAuthenticatorServiceComponent.class);

    private static RealmService realmService;

    protected void activate(ComponentContext ctxt) {

        CustomAuthenticator customAuth = new CustomAuthenticator();
        Hashtable<String, String> props = new Hashtable<String, String>();

        ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), customAuth, props);

        if (log.isDebugEnabled()) {
            log.info("CustomAuthenticator bundle is activated");
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.info("CustomAuthenticator bundle is deactivated");
        }
    }

    protected void setRealmService(RealmService realmService) {
        log.debug("Setting the Realm Service");
        CustomAuthenticatorServiceComponent.realmService = realmService;
    }

    protected void unsetRealmService(RealmService realmService) {
        log.debug("UnSetting the Realm Service");
        CustomAuthenticatorServiceComponent.realmService = null;
    }

    public static RealmService getRealmService() {
        return realmService;
    }

}
