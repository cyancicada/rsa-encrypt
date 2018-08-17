package com.vector;

import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Unit test for simple App.
 */
public class AppTest 
{
    @Before
    public  void start(){
        System.out.println("RAS 加密测试现在开始");
    }
    /**
     * Rigorous Test :-)
     */
    @Test
    public void test() throws Exception
    {
        String             d    = "I love you so much";
        Map<String,Object> keys = RSAUtils.generateKeys(1024);
        System.out.println("================生成签名如下============");
        String s=RSAUtils.sign(d.getBytes(),RSAUtils.getPrivateKey(keys));
        System.out.println(s);
        System.out.println("================生成签名结束============END");
        System.out.println("================公钥加密============");
        byte[] bs = RSAUtils.encryptByPublicKey(d.getBytes(),RSAUtils.getPublicKey(keys));
        System.out.println(new String(bs, StandardCharsets.UTF_8));
        System.out.println("================公钥加密============END");
        System.out.println("================私钥解密============");
        byte[] d2 = RSAUtils.decryptByPrivateKey(bs,RSAUtils.getPrivateKey(keys));
        System.out.println(new String(d2,StandardCharsets.UTF_8));
        System.out.println("================私钥解密============END");
        System.out.println("================签名验证============");
        System.out.println(RSAUtils.verify(d.getBytes(),RSAUtils.getPublicKey(keys),s));
        System.out.println("================签名验证============END");
    }
    @After
    public void end(){
        System.out.println("RAS 加密测试已经结束了");
    }
}
