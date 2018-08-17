# rsa-encrypt

测试加密(可以直接运行com.vector.AppTest)
```java

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

```



#测试结果

```$xslt

RAS 加密测试现在开始
================生成签名如下============
fC+COD0YA6CQlyPWrB0APVif5zMXo+y7QTPrYhTsnH66y/rUt2NojEMB0/ot39AOAJfbcsB3ahYPPr+8u1cNdK8DtxeXGwjCeAbLMKy6sKqtH3f9tMHoC4125nvAxfPrZRjH+N23Aa52gcD5hWXHpdncz/zxqrzkv3J6XDqAoMc=
================生成签名结束============END
================公钥加密============
D�P�*�~	r�-���/OL�>em-��A.M
================公钥加密============END
================私钥解密============
I love you so much
================私钥解密============END
================签名验证============
true
================签名验证============END
RAS 加密测试已经结束了

Process finished with exit code 0

```