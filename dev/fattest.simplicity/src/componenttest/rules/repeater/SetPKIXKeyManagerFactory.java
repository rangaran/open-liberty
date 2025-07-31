package componenttest.rules.repeater;

import componenttest.rules.repeater.KeyManagerFactoryReplacementAction;

import java.security.Security;

import com.ibm.websphere.simplicity.log.Log;

import static org.junit.Assert.assertFalse;
import componenttest.custom.junit.runner.RepeatTestFilter;

public class SetPKIXKeyManagerFactory extends KeyManagerFactoryReplacementAction {
    private static final Class<?> c = SetPKIXKeyManagerFactory.class;
    public static final String ID = "PKIX_Key_Manager_Factory";
    public SetPKIXKeyManagerFactory() {
        if (isPKIXEnabledInConfig()) {
            Log.info(c, "isEnabled", "Skipping action as PKIX is already set for ssl.KeyManagerFactory.algorithm");
        }else{
            Security.setProperty("ssl.KeyManagerFactory.algorithm", "PKIX");
        }
        withID(ID);
    }

    @Override
    public String toString() {
        return "Set ssl.KeyManagerFactory.algorithm=PKIX";
    }
}