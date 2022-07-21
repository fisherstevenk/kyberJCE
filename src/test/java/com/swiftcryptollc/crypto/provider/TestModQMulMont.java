/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.swiftcryptollc.crypto.provider;

import com.swiftcryptollc.crypto.provider.kyber.Ntt;
import org.junit.jupiter.api.Test;

/**
 *
 * @author Steven K Fisher <swiftcryptollc@gmail.com>
 */
public class TestModQMulMont {
 
    @Test
    public void testMod(){
         short t = Ntt.modQMulMont((short)2970, (short)-52);
         System.out.println(t);
                   
    }
}
