package net.easyappsec.sodium.util;

@FunctionalInterface
public interface FiveParamFunction<T, U, V, W, X, R>  {

    public R apply(T t, U u, V v, W w, X x);

}
