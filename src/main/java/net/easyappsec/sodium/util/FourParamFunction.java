package net.easyappsec.sodium.util;

@FunctionalInterface
public interface FourParamFunction<T, U, V, W, R> {
    public R apply(T t, U u, V v, W w);
}
