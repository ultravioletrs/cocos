package org.eclipse.edc.connector.cocos.spi;

import java.util.Optional;

public class CocosContextHolder {

    private static final ThreadLocal<String> activeVmIp = new ThreadLocal<>();

    private CocosContextHolder() {}

    public static void setActiveVmIp(String vmIp) {
        activeVmIp.set(vmIp);
    }

    public static Optional<String> getActiveVmIp() {
        return Optional.ofNullable(activeVmIp.get());
    }

    public static void clear() {
        activeVmIp.remove();
    }
}
