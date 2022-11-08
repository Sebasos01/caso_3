package utility;

import java.util.Arrays;

public final class Log {
    public static void log(String... msg) {
        Arrays.stream(msg).forEach(System.out::print);
        System.out.print("\n");
    }

    public static Exception err(String... msg) {
        return new Exception(String.join(" ", msg));
    }
}
