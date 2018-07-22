package com.chuili.ecdhkeyexchange;

import com.chuili.ecdhkeyexchange.util.DataHelper;

import org.junit.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.junit.Assert.*;

public class DataHelperTest {
    @Test
    public void test_byteArrayToHexaStr() {
        byte[] input = {(byte) 0x4D, (byte) 0x56, (byte) 0xAE, (byte) 0x3F, (byte) 0x54};
        String output = DataHelper.byteArrayToHexaStr(input);
        assertEquals("4D56AE3F54", output);
    }

    @Test
    public void test_convertDigit_smallerThanTen() {
        try {
            Method method = DataHelper.class.getDeclaredMethod("convertDigit", int.class);
            method.setAccessible(true);
            char output = (char) method.invoke(null, 9);
            assertEquals('9', output);
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            assertTrue(false);
        }
    }

    @Test
    public void test_convertDigit_greaterThanTen() {
        try {
            Method method = DataHelper.class.getDeclaredMethod("convertDigit", int.class);
            method.setAccessible(true);
            char output = (char) method.invoke(null, 14);
            assertEquals('e', output);
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            assertTrue(false);
        }
    }
}