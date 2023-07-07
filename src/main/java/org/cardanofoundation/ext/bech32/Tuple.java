package org.cardanofoundation.ext.bech32;

public class Tuple<T, Z> {
    public T _1;
    public Z _2;

    public Tuple(T _1, Z _2) {
        this._1 = _1;
        this._2 = _2;
    }
}