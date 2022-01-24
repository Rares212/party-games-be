package com.mps.partygames.util;

public class UserUtil {
    private UserUtil() {}

    private static final String emailRegex = "^(.+)@(.+)$";
    private static final String universityEmailTermination = "upb.ro";

    public static boolean isValidEmail(String email) {
        if (email.matches(emailRegex)) {
            return email.endsWith(universityEmailTermination);
        }
        return false;
    }
}
