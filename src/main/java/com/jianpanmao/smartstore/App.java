package com.jianpanmao.smartstore;

import cfca.sm2.signature.SM2PrivateKey;
import cfca.sm2rsa.common.Mechanism;
import cfca.sm2rsa.common.PKIException;
import cfca.util.CertUtil;
import cfca.util.EnvelopeUtil;
import cfca.util.KeyUtil;
import cfca.util.SignatureUtil2;
import cfca.util.cipher.lib.JCrypto;
import cfca.util.cipher.lib.Session;
import cfca.x509.certificate.X509Cert;
import cfca.x509.certificate.X509CertHelper;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import org.junit.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Administrator on 2017/11/22.
 */
public class App {

    private static String context = "{\"txnSeq\":\"\",\"platformId\":\"A00012017060000000691\",\"outMchntId\":\"O01002016070000000635\",\"cmbcMchntId\":\"M29002017110000030817\",\"message\":\"\"}";
    //private static String context = "{\"txnSeq\":\"100860001111111000\",\"platformId\":\"A00002016120000000294\",\"outMchntId\":\"\",\"cmbcMchntId\":\"\",\"message\":\"\"}";
   /* private static String context = "{\"txnSeq\":\"100860001111111000\",\"platformId\":\"A00002016080000000049\",\"operId\":\"10010A0001\",\"outMchntId\":\"O01002016070000000789\",\"mchntName\":\"Demo进件测试商户\",\n" +
            "\"parentMchntId\":\"\",\"industryId\":\"105\",\"acdCode\":\"130105\",\"province\":\"河北省\",\n" +
            "\"city\":\"石家庄市\",\"address\":\"新华区华西路53号\",\n" +
            "\"licId\":\"1301053123456\",\"licIdValidity\":\"\",\"corpName\":\"唐门\",\n" +
            "\"idtCard\":\"130105187808235612\",\"contactName\":\"唐三角\",\n" +
            "\"telephone\":\"13880880808\",\"servTel\":\"13839795841\",\"identification\":\"\",\"remark\":\"\",\"message\":\"\",\"devType\":\"1\",\"autoSettle\":\"1\"}";*/
    private static Session session;

    static {
        try {
            JCrypto.getInstance().initialize(JCrypto.JSOFT_LIB, null);
            session = JCrypto.getInstance().openSession(JCrypto.JSOFT_LIB);
        } catch (PKIException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        String sign = getSign(context);
        System.out.println("--------------------------------------");
        System.out.println("签名：");
        System.out.println(sign);

        String signContext = sign(sign, context);
        System.out.println("--------------------------------------");
        System.out.println("加密前：");
        System.out.println(signContext);

        String encryptContext = encrypt(signContext);
        System.out.println("--------------------------------------");
        System.out.println("加密后：");
        System.out.println(encryptContext);


       // encryptContext="MIIB6AYKKoEcz1UGAQQCA6CCAdgwggHUAgECMYGdMIGaAgECgBS1x/e/puEJbLQnTtwm2y/+fP1b2jANBgkqgRzPVQGCLQMFAARwA0Cb9GsPb5zFziSwicmOh8e122l4Jt6CsrSEEt+h182Tq0IuiDPNvkOyND4rcfKUHxrG9SV17fKfsK1dwL70V21D09eOzBO5kFIE2iiFVa22Uh41VchYl8mniQMFtFj2iAf6pQU5XlaeQD3V55uiuTCCAS0GCiqBHM9VBgEEAgEwGwYHKoEcz1UBaAQQ2ctqTaq5tzLBdOX8harYEYCCAQAJjPVCNvxSapA4YTWDMXOIwuxjvyfXVmv2T2/9G32P8Bm7xSCRVOs0XNKgmiaGPfeutEH7U2Awwx2EyBqr/ypt+5E7aNgw181aROE4Xouzxu7+j2MqdMFFbtCTt68dj0ke7HQ4zNRjIAEJNr2aSOx5yk5OKVbAuSv/W+oNoaPlrUle+LO3eBY/J65hwqsywIwPmpXCh7ipB7RO3Vjy65z4SaWFndOVf+9yEUZYwITAzkU3SVYuFDdZVnByVxknUEyp+5OhqcQQbhd+cmL8ApfLvlIdR957X1Ngrjz3XumjD/Ej3pBlwN52IuMnaNlx25wHLa/bxre9cUQ3vERrmLWI";


        RestTemplate restTemplate=new RestTemplate();

        Map<String,String> data =new HashMap<String, String>();

        data.put("businessContext", encryptContext);


        ResponseEntity<HashMap> stringResponseEntity = restTemplate.postForEntity("http://wxpay.cmbc.com.cn:1080/mobilePlatform/lcbpService/queryMchnt.do", data, HashMap.class);


        System.out.println(stringResponseEntity.getBody());


        String dncryptContext = dncrypt((String)stringResponseEntity.getBody().get("businessContext"));
        System.out.println("--------------------------------------");
        System.out.println("解密后：");
        System.out.println(dncryptContext);

        String signChkResult = signCheck(dncryptContext);
        System.out.println("--------------------------------------");
        System.out.println("验证签名结果：");
        System.out.println(signChkResult);
    }





    @Test
    public void API_ZFBSCAN(){


        String context="{\"platformId\":\"A00012017060000000691\",\"merchantNo\":\"M29002017110000030909\",\"merchantSeq\":\"A0001201706000000069131\",\"mchSeqNo\":\"A00012017050000000545T20171127094901R61\",\"selectTradeType\":\"API_ZFBSCAN\",\"amount\":\"1\",\"orderInfo\":\"统一下单DEMO-API_ZFBSCAN\",\"notifyUrl\":\"https://wxpay.cmbc.com.cn/cmbcpaydemo/NoticeServlet?name=notice\",\"remark\":\"MTQwMDAwMDAwMDAwMDAwMDAw\",\"transDate\":\"20171127\",\"transTime\":\"20171127094904956\",\"inExtData\":\"测试请求扩展大字段\"}";

        String sign = getSign(context);
        System.out.println("--------------------------------------");
        System.out.println("签名：");
        System.out.println(sign);

        String signContext = sign(sign, context);
        System.out.println("--------------------------------------");
        System.out.println("加密前：");
        System.out.println(signContext);

        String encryptContext = encrypt(signContext);
        System.out.println("--------------------------------------");
        System.out.println("加密后：");
        System.out.println(encryptContext);




        RestTemplate restTemplate=new RestTemplate();

        Map<String,String> data =new HashMap<String, String>();

        data.put("businessContext", encryptContext);


        ResponseEntity<HashMap> stringResponseEntity = restTemplate.postForEntity("http://wxpay.cmbc.com.cn:1080/mobilePlatform/appserver/lcbpPay.do", data, HashMap.class);


        System.out.println(stringResponseEntity.getBody());


        String dncryptContext = dncrypt((String)stringResponseEntity.getBody().get("businessContext"));
        System.out.println("--------------------------------------");
        System.out.println("解密后：");
        System.out.println(dncryptContext);

        String signChkResult = signCheck(dncryptContext);
        System.out.println("--------------------------------------");
        System.out.println("验证签名结果：");
        System.out.println(signChkResult);
    }


    /**
     * 退款
     */
    @Test
    public void CANCEL(){


        String context="{\"platformId\":\"A00012017060000000691\",\"merchantNo\":\"M29002017110000030909\",\"merchantSeq\":\"A0001201706000000069136\",\"mchSeqNo\":\"A0001201706000000069135\",\"orderAmount\":\"1\",\"orderNote\":\"退款\",\"reserve\":\"下错单了\"}";

        String sign = getSign(context);
        System.out.println("--------------------------------------");
        System.out.println("签名：");
        System.out.println(sign);

        String signContext = sign(sign, context);
        System.out.println("--------------------------------------");
        System.out.println("加密前：");
        System.out.println(signContext);

        String encryptContext = encrypt(signContext);
        System.out.println("--------------------------------------");
        System.out.println("加密后：");
        System.out.println(encryptContext);




        RestTemplate restTemplate=new RestTemplate();

        Map<String,String> data =new HashMap<String, String>();

        data.put("businessContext", encryptContext);


        ResponseEntity<HashMap> stringResponseEntity = restTemplate.postForEntity("http://wxpay.cmbc.com.cn:1080/mobilePlatform/appserver/cancelTrans.do", data, HashMap.class);


        System.out.println(stringResponseEntity.getBody());


        String dncryptContext = dncrypt((String)stringResponseEntity.getBody().get("businessContext"));
        System.out.println("--------------------------------------");
        System.out.println("解密后：");
        System.out.println(dncryptContext);

        String signChkResult = signCheck(dncryptContext);
        System.out.println("--------------------------------------");
        System.out.println("验证签名结果：");
        System.out.println(signChkResult);
    }


    /**
     * 商户提现
     */
    @Test
    public void wddp(){


        String context="{\"merchantNo\":\"M29002017110000030909\",\"platformId\":\"A00012017060000000691\",\"tradeAmount\":\"1\",\"tradeNote\":\"\"}";

        String sign = getSign(context);
        System.out.println("--------------------------------------");
        System.out.println("签名：");
        System.out.println(sign);

        String signContext = sign(sign, context);
        System.out.println("--------------------------------------");
        System.out.println("加密前：");
        System.out.println(signContext);

        String encryptContext = encrypt(signContext);
        System.out.println("--------------------------------------");
        System.out.println("加密后：");
        System.out.println(encryptContext);




        RestTemplate restTemplate=new RestTemplate();

        Map<String,String> data =new HashMap<String, String>();

        data.put("businessContext", encryptContext);


        ResponseEntity<HashMap> stringResponseEntity = restTemplate.postForEntity("http://wxpay.cmbc.com.cn:1080/mobilePlatform/appserver/wddp.do", data, HashMap.class);


        System.out.println(stringResponseEntity.getBody());


        String dncryptContext = dncrypt((String)stringResponseEntity.getBody().get("businessContext"));
        System.out.println("--------------------------------------");
        System.out.println("解密后：");
        System.out.println(dncryptContext);

        String signChkResult = signCheck(dncryptContext);
        System.out.println("--------------------------------------");
        System.out.println("验证签名结果：");
        System.out.println(signChkResult);
    }


    /**
     * API_WXQRCODE
     * 商户提现信息查询
     */
    @Test
    public void WDDPQ(){


        String context="{\"merchantNo\":\"M29002017110000030817\",\"platformId\":\"A00012017060000000691\",\"tradeAmount\":\"\",\"tradeNote\":\"\"}";

        String sign = getSign(context);
        System.out.println("--------------------------------------");
        System.out.println("签名：");
        System.out.println(sign);

        String signContext = sign(sign, context);
        System.out.println("--------------------------------------");
        System.out.println("加密前：");
        System.out.println(signContext);

        String encryptContext = encrypt(signContext);
        System.out.println("--------------------------------------");
        System.out.println("加密后：");
        System.out.println(encryptContext);




        RestTemplate restTemplate=new RestTemplate();

        Map<String,String> data =new HashMap<String, String>();

        data.put("businessContext", encryptContext);


        ResponseEntity<HashMap> stringResponseEntity = restTemplate.postForEntity("http://wxpay.cmbc.com.cn:1080/mobilePlatform/appserver/wddpQuery.do", data, HashMap.class);


        System.out.println(stringResponseEntity.getBody());


        String dncryptContext = dncrypt((String)stringResponseEntity.getBody().get("businessContext"));
        System.out.println("--------------------------------------");
        System.out.println("解密后：");
        System.out.println(dncryptContext);

        String signChkResult = signCheck(dncryptContext);
        System.out.println("--------------------------------------");
        System.out.println("验证签名结果：");
        System.out.println(signChkResult);
    }







    /**
     * 微信正扫
     */
    @Test
    public void API_WXQRCODE(){


        String context="{\"platformId\":\"A00012017060000000691\",\"merchantNo\":\"M29002017110000030909\",\"merchantSeq\":\"A0001201706000000069147\",\"mchSeqNo\":\"A00012017050000000545T20171127180227R867\",\"selectTradeType\":\"API_ZFBQRCODE\",\"amount\":\"1\",\"orderInfo\":\"统一下单DEMO-API_ZFBQRCODE\",\"notifyUrl\":\"http://vszapp.com:8111/notice\",\"remark\":\"\",\"transDate\":\"20171127\",\"transTime\":\"2017112718020494\",\"inExtData\":\"测试请求扩展大字段\"}";

        String sign = getSign(context);
        System.out.println("--------------------------------------");
        System.out.println("签名：");
        System.out.println(sign);

        String signContext = sign(sign, context);
        System.out.println("--------------------------------------");
        System.out.println("加密前：");
        System.out.println(signContext);

        String encryptContext = encrypt(signContext);
        System.out.println("--------------------------------------");
        System.out.println("加密后：");
        System.out.println(encryptContext);




        RestTemplate restTemplate=new RestTemplate();

        Map<String,String> data =new HashMap<String, String>();

        data.put("businessContext", encryptContext);


        ResponseEntity<HashMap> stringResponseEntity = restTemplate.postForEntity("http://wxpay.cmbc.com.cn:1080/mobilePlatform/appserver/lcbpPay.do", data, HashMap.class);


        System.out.println(stringResponseEntity.getBody());


        String dncryptContext = dncrypt((String)stringResponseEntity.getBody().get("businessContext"));
        System.out.println("--------------------------------------");
        System.out.println("解密后：");
        System.out.println(dncryptContext);

        String signChkResult = signCheck(dncryptContext);
        System.out.println("--------------------------------------");
        System.out.println("验证签名结果：");
        System.out.println(signChkResult);
    }

    /**
     * 签名
     *
     * @param sign
     * @param context
     * @return
     */
    public static String sign(String sign, String context) {
        GsonBuilder builder = new GsonBuilder();
        builder.disableHtmlEscaping();
        Gson gson = builder.create();
        Map<String, String> paramMap = new HashMap<String, String>();
        paramMap.put("sign", sign);
        paramMap.put("body", context);
        String signInfo = gson.toJson(paramMap); // 待加密字符串
        return signInfo;
    }

    /**
     * 加密
     *
     * @param signContext
     *            需要加密的报文
     * @return
     */
    @SuppressWarnings("deprecation")
    public static String encrypt(String signContext) {
        String certAbsPath = Config.getProperty("bankPublicKey");
        X509Cert cert = null;
        try {
            cert = X509CertHelper.parse(certAbsPath);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PKIException e) {
            e.printStackTrace();
        }
        X509Cert[] certs = { cert };
        byte[] encryptedData = null;
        try {
            encryptedData = EnvelopeUtil.envelopeMessage(signContext.getBytes("UTF8"), Mechanism.SM4_CBC, certs);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (PKIException e) {
            e.printStackTrace();
        }
        String encodeText = null;
        try {
            encodeText = new String(encryptedData, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return encodeText;
    }

    /**
     * 解密
     *
     * @param encryptContext
     *            需要解密的报文
     * @return
     */
    public static String dncrypt(String encryptContext) {
        String priKeyAbsPath = Config.getProperty("merchantPrivateKey");
        String priKeyPWD = Config.getProperty("merchantPwd");
        String decodeText = null;
        try {
            PrivateKey priKey = KeyUtil.getPrivateKeyFromSM2(priKeyAbsPath, priKeyPWD);
            X509Cert cert = CertUtil.getCertFromSM2(priKeyAbsPath);
            byte[] sourceData = EnvelopeUtil.openEvelopedMessage(encryptContext.getBytes("UTF8"), priKey, cert, session);
            decodeText = new String(sourceData, "UTF8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decodeText;
    }

    /**
     * 验证签名
     *
     * @param dncryptContext
     *            需要验证签名的明文
     * @return
     */
    public static String signCheck(String dncryptContext) {
        String certAbsPath = Config.getProperty("bankPublicKey");
        Gson gson = new Gson();
        @SuppressWarnings("unchecked")
        Map<String, Object> paraMap = gson.fromJson(dncryptContext, Map.class);
        String sign = paraMap.get("sign").toString();
        String body = paraMap.get("body").toString();
        boolean isSignOK = false;
        try {
            X509Cert cert = X509CertHelper.parse(certAbsPath);
            PublicKey pubKey = cert.getPublicKey();
            isSignOK = new SignatureUtil2().p1VerifyMessage(Mechanism.SM3_SM2, body.getBytes("UTF8"),
                    sign.getBytes(), pubKey, session);
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (isSignOK) {
            return "验签通过";
        } else {
            return "验签不通过";
        }
    }

    private static String getSign(String context) {
        String priKeyAbsPath = Config.getProperty("merchantPrivateKey");
        String priKeyPWD = Config.getProperty("merchantPwd");
        String sign = "";
        try {
            JCrypto.getInstance().initialize(JCrypto.JSOFT_LIB, null);
            Session session = JCrypto.getInstance().openSession(JCrypto.JSOFT_LIB);
            SM2PrivateKey priKey = KeyUtil.getPrivateKeyFromSM2(priKeyAbsPath, priKeyPWD);
            sign = new String(
                    new SignatureUtil2().p1SignMessage(Mechanism.SM3_SM2, context.getBytes("UTF8"), priKey, session));
        } catch (PKIException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return sign;
    }
}
