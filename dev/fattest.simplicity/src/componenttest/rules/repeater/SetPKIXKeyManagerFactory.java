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
        String originalKeyManagerFactoryAlgorithm = Security.getProperty("ssl.KeyManagerFactory.algorithm");
        Log.info(c, "setup", "Current KeyManager Factory algorithm: " + originalKeyManagerFactoryAlgorithm);
        if ("PKIX".equals(originalKeyManagerFactoryAlgorithm)) {
            Log.info(c, "SetPKIXKeyManagerFactory", "Skipping action as PKIX is already set for ssl.KeyManagerFactory.algorithm");
        }else{
            Log.info(c, "SetPKIXKeyManagerFactory", "Setting ssl.KeyManagerFactory.algorithm to PKIX");
            Security.setProperty("ssl.KeyManagerFactory.algorithm", "PKIX");
        }
        withID(ID);
    }

    @Override
    public boolean isEnabled() {
        String algorithm = Security.getProperty("ssl.KeyManagerFactory.algorithm");
        boolean isEnabled = !"PKIX".equals(algorithm);
        Log.info(c, "isEnabled", "Current algorithm is: " + algorithm + " is action enabled: "+ isEnabled);
        return isEnabled;
    }

    @Override
    public String toString() {
        return "Set ssl.KeyManagerFactory.algorithm=PKIX repeat action";
    }
}