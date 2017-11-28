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
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
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

    //private static String context = "{\"txnSeq\":\"100860001111111000\",\"platformId\":\"A00012017060000000691\",\"operId\":\"10010A0001\",\"dataSrc\":\"2\",\"outMchntId\":\"O01002016070000000635\",\"mchntName\":\"键盘猫进件测试商户\",\"mchntFullName\":\"中国移动\",\"parentMchntId\":\"\",\"acdCode\":\"350203\",\"province\":\"河北省\",\"city\":\"石家庄市\",\"address\":\"新华区华西路53号\",\"licId\":\"35020320160831\",\"licValidity\":\"20301231\",\"corpName\":\"唐门\",\"idtCard\":\"130105187808235612\",\"contactName\":\"测试1247850073\",\"telephone\":\"13880880808\",\"servTel\":\"13839795841\",\"identification\":\"\",\"remark\":\"\",\"message\":\"\",\"devType\":\"\",\"isCert\":\"\",\"autoSettle\":\"\"}";
    //private static String context = "{\"txnSeq\":\"100860001111111000\",\"platformId\":\"A00002016120000000294\",\"outMchntId\":\"\",\"cmbcMchntId\":\"\",\"message\":\"\"}";
    //private static String context = "{\"txnSeq\":\"100860001111111000\",\"platformId\":\"A00002016120000000294\",\"outMchntId\":\"\",\"cmbcMchntId\":\"\",\"message\":\"\"}";

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

    }

    //M29002017110000030898-1
    //M29002017110000030907-2
    //M29002017110000030911-O010020160700000006351
    @Test
    public void mchntAdd(){
        String context="{\"txnSeq\":\"100860001111111000\",\"platformId\":\"A00012017060000000691\",\"operId\":\"10010A0001\",\"dataSrc\":\"2\",\"outMchntId\":\"O010020160700000006351\",\"mchntName\":\"Demo进件测试商户\",\"mchntFullName\":\"中国移动\",\"parentMchntId\":\"\",\"acdCode\":\"350203\",\"province\":\"河北省\",\"city\":\"石家庄市\",\"address\":\"新华区华西路53号\",\"licId\":\"35020320160831\",\"licValidity\":\"20301231\",\"corpName\":\"唐门\",\"idtCard\":\"130105187808235612\",\"contactName\":\"测试1247850073\",\"telephone\":\"13880880808\",\"servTel\":\"13839795841\",\"identification\":\"\",\"remark\":\"\",\"message\":\"\",\"devType\":\"1\",\"isCert\":\"0\",\"autoSettle\":\"6\"}";
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



        ResponseEntity<HashMap> stringResponseEntity = restTemplate.postForEntity("http://wxpay.cmbc.com.cn:1080/mobilePlatform/lcbpService/mchntAdd.do", data, HashMap.class);


        System.out.println(stringResponseEntity.getBody().get("businessContext"));


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
    public void mchntUpd(){
        String context="{\"txnSeq\":\"100860001111111000\",\"platformId\":\"A00012017060000000691\",\"operId\":\"10010A0002\",\"outMchntId\":\"O010020160700000006351\",\"cmbcMchntId\":\"M29002017110000030911\",\"mchntName\":\"Demo进件修改测试商户\",\"mchntFullName\":\"中国山东找蓝翔\",\"address\":\"新华区华西路53号\",\"licId\":\"1301053123456\",\"licValidity\":\"20301231\",\"corpName\":\"唐门\",\"idtCard\":\"130105187808235612\",\"contactName\":\"测试1247850073\",\"telephone\":\"13880880808\",\"identification\":\"\",\"remark\":\"\",\"message\":\"\",\"isCert\":\"1\",\"autoSettle\":\"6\"}";
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



        ResponseEntity<HashMap> stringResponseEntity = restTemplate.postForEntity("http://wxpay.cmbc.com.cn:1080/mobilePlatform/lcbpService/mchntUpd.do", data, HashMap.class);


        System.out.println(stringResponseEntity.getBody().get("businessContext"));


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
    public void queryMchnt(){
        String context="{\"txnSeq\":\"100860001111111000\",\"platformId\":\"A00012017060000000691\",\"outMchntId\":\"O010020160700000006351\",\"cmbcMchntId\":\"M29002017110000030911\",\"message\":\"\"}";
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



        ResponseEntity<HashMap> stringResponseEntity = restTemplate.postForEntity("http://wxpay.cmbc.com.cn:1080/mobilePlatform/lcbpService/queryMchnt.do", data, HashMap.class);


        System.out.println(stringResponseEntity.getBody().get("businessContext"));


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
     * 商户支付通道信息绑定
     */
    @Test
    public void chnlAdd(){
        String context="{\"txnSeq\":\"100860001111111000\",\"platformId\":\"A00012017060000000691\",\"operId\":\"10086A0001\",\"outMchntId\":\"O010020160700000006351\",\"cmbcMchntId\":\"M29002017110000030911\",\"industryId\":\"102\",\"dayLimit\":\"20000000\",\"monthLimit\":\"50000000\",\"fixFeeRate\":\"0.38\",\"specFeeRate\":\"\",\"account\":\"6226223380006109\",\"acctName\":\"测试1247850073\",\"acctTelephone\":\"\",\"pbcBankId\":\"305526061005\",\"idCode\":\"\",\"message\":\"\",\"apiCode\":\"0005\",\"operateType\":\"1\",\"acctType\":\"1\",\"idType\":\"01\",\"doWxConfig\":\"0\"}";
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



        ResponseEntity<HashMap> stringResponseEntity = restTemplate.postForEntity("http://wxpay.cmbc.com.cn:1080/mobilePlatform/lcbpService/chnlAdd.do", data, HashMap.class);


        System.out.println(stringResponseEntity.getBody().get("businessContext"));


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
     * 商户支付通道信息查询
     */
    @Test
    public void CHNL_QUE(){
        String context="{\"txnSeq\":\"100860001111111000\",\"platformId\":\"A00012017060000000691\",\"outMchntId\":\"O010020160700000006351\",\"cmbcMchntId\":\"M29002017110000030911\",\"message\":\"\",\"apiCode\":\"0005\"}";
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



        ResponseEntity<HashMap> stringResponseEntity = restTemplate.postForEntity("http://wxpay.cmbc.com.cn:1080/mobilePlatform/lcbpService/queryChnl.do", data, HashMap.class);


        System.out.println(stringResponseEntity.getBody().get("businessContext"));


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
     * 商户支付通道信息修改
     */
    @Test
    public void CHNL_UPD(){
        String context="{\"txnSeq\":\"100860001111111000\",\"platformId\":\"A00012017060000000691\",\"operId\":\"10086A0001\",\"outMchntId\":\"O010020160700000006351\",\"cmbcMchntId\":\"M29002017110000030911\",\"cmbcSignId\":\"S29002017110000421176\",\"dayLimit\":\"2000000\",\"monthLimit\":\"5000000\",\"fixFeeRate\":\"0.38\",\"specFeeRate\":\"\",\"account\":\"6226223380006109\",\"acctName\":\"测试1247850073\",\"acctTelephone\":\"\",\"pbcBankId\":\"305526061005\",\"idCode\":\"\",\"message\":\"\",\"apiCode\":\"0005\",\"acctType\":\"1\",\"idType\":\"01\"}";
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



        ResponseEntity<HashMap> stringResponseEntity = restTemplate.postForEntity("http://wxpay.cmbc.com.cn:1080/mobilePlatform/lcbpService/chnlUpd.do", data, HashMap.class);


        System.out.println(stringResponseEntity.getBody().get("businessContext"));


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
    public void upload(){
        String context="{\"txnSeq\":\"100860001111111000\",\"platformId\":\"A00012017060000000691\",\"operId\":\"10086A0001\",\"outMchntId\":\"O010020160700000006351\",\"cmbcMchntId\":\"M29002017110000030911\",\"upFileCount\":\"2\",\"md5s\":{\"002\":\"40c3072a456cfce6bfc45535570bcd55\",\"003\":\"ecce64b02bddd08354639f0f7bed771\"},\"message\":\"\",\"edType\":\"01\"}";
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


        String url = "http://wxpay.cmbc.com.cn:1080/mobilePlatform/lcbpService/upload.do";
        RestTemplate client = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
//  请勿轻易改变此提交方式，大部分的情况下，提交方式都是表单提交
        headers.setContentType(MediaType.valueOf(MediaType.MULTIPART_FORM_DATA_VALUE));
//  封装参数，千万不要替换为Map与HashMap，否则参数无法传递
        MultiValueMap<String, String> params= new LinkedMultiValueMap<String, String>();
//  也支持中文
        params.add("uploadContext", encryptContext);
        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<MultiValueMap<String, String>>(params, headers);
//  执行HTTP请求
        ResponseEntity<String> response = client.exchange(url, HttpMethod.POST, requestEntity, String.class);
//  输出结果
        System.out.println(response.getBody());



       // ResponseEntity<HashMap> stringResponseEntity = restTemplate.postForEntity("http://wxpay.cmbc.com.cn:1080/mobilePlatform/lcbpService/upload.do", data, HashMap.class);


        //System.out.println(stringResponseEntity);


        String dncryptContext = dncrypt(response.getBody());
        System.out.println("--------------------------------------");
        System.out.println("解密后：");
        System.out.println(dncryptContext);

        String signChkResult = signCheck(dncryptContext);
        System.out.println("--------------------------------------");
        System.out.println("验证签名结果：");
        System.out.println(signChkResult);
    }


    /**
     * 微信公众号跳转
     */
    @Test
    public void API_WXAPP(){
        String context="{\"platformId\":\"A00012017060000000691\",\"merchantNo\":\"M29002017110000030909\",\"merchantSeq\":\"A000120170600000006912017112803\",\"mchSeqNo\":\"A000120170600000006912017112803\",\"selectTradeType\":\"API_WXAPP\",\"amount\":\"1\",\"orderInfo\":\"统一下单DEMO-API_WXAPP\",\"notifyUrl\":\"https://39.108.49.56\",\"remark\":\"\",\"transDate\":\"20171128\",\"transTime\":\"20171128122204720\",\"inExtData\":\"测试请求扩展大字段\",\"spbillCreateIp\":\"39.108.49.56\"}";
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


        System.out.println(stringResponseEntity);


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
        String context="{\"platformId\":\"A00012017060000000691\",\"merchantNo\":\"M29002017110000030955\",\"merchantSeq\":\"M2900201711000003095503\",\"mchSeqNo\":\"M2900201711000003095503\",\"selectTradeType\":\"API_WXQRCODE\",\"amount\":\"1\",\"orderInfo\":\"统一下单DEMO-API_WXQRCODE\",\"notifyUrl\":\"http://39.108.49.56\",\"remark\":\"\",\"transDate\":\"20171128\",\"transTime\":\"20171128111604107\",\"inExtData\":\"测试请求扩展大字段\"}";
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


        System.out.println(stringResponseEntity);


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
     * 微信反扫
     */
    @Test
    public void API_WXSCAN(){
        String context="{\"platformId\":\"A00012017060000000691\",\"merchantNo\":\"M29002017110000030955\",\"merchantSeq\":\"M2900201711000003095504\",\"mchSeqNo\":\"11\",\"selectTradeType\":\"API_WXSCAN\",\"amount\":\"1\",\"orderInfo\":\"统一下单DEMO-API_WXSCAN\",\"notifyUrl\":\"http://39.108.49.56\",\"remark\":\"MTQwMDAwMDAwMDAwMDAwMDAw\",\"transDate\":\"20171126\",\"transTime\":\"20171126111304888\",\"inExtData\":\"测试请求扩展大字段\"}";
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


        System.out.println(stringResponseEntity);


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
     * 微信H5
     */
    @Test
    public void H5_WXMWEB(){
        String context="{\"platformId\":\"A00012017060000000691\",\"merchantNo\":\"M29002017110000030817\",\"merchantSeq\":\"12345678A00012017060000000691\",\"mchSeqNo\":\"12345678A00012017060000000691\",\"selectTradeType\":\"H5_WXMWEB\",\"amount\":\"1\",\"orderInfo\":\"统一下单DEMO-H5_WXMWEB\",\"notifyUrl\":\"https://wxpay.cmbc.com.cn/cmbcpaydemo/NoticeServlet?name=notice\",\"remark\":\"MTIwMDAwMDAwMDAwMDAwMDAw\",\"transDate\":\"20171125\",\"transTime\":\"20171125204504288\",\"inExtData\":\"测试请求扩展大字段\",\"spbillCreateIp\":\"110.184.160.129\"}";
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


        System.out.println(stringResponseEntity);


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
     * 支付宝正扫
     */
    @Test
    public void API_ZFBQRCODE(){
        String context="{\"platformId\":\"A00012017060000000691\",\"merchantNo\":\"M29002017110000030909\",\"merchantSeq\":\"A000120170600000006912017112614\",\"mchSeqNo\":\"11\",\"selectTradeType\":\"API_ZFBQRCODE\",\"amount\":\"1\",\"orderInfo\":\"统一下单DEMO-API_ZFBQRCODE\",\"notifyUrl\":\"https://wxpay.cmbc.com.cn/cmbcpaydemo/NoticeServlet?name=notice\",\"remark\":\"\",\"transDate\":\"20171126\",\"transTime\":\"20171126111304888\",\"inExtData\":\"测试请求扩展大字段\"}";
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


        System.out.println(stringResponseEntity);


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
     * 支付宝反扫
     */
    @Test
    public void API_ZFBSCAN(){
        String context="{\"platformId\":\"A00012017060000000691\",\"merchantNo\":\"M29002017110000030909\",\"merchantSeq\":\"A000120170600000006912017112619\",\"mchSeqNo\":\"11\",\"selectTradeType\":\"API_ZFBSCAN\",\"amount\":\"1\",\"orderInfo\":\"统一下单DEMO-API_ZFBSCAN\",\"notifyUrl\":\"https://wxpay.cmbc.com.cn/cmbcpaydemo/NoticeServlet?name=notice\",\"remark\":\"MTQxMDAwMDAwMDAwMDAwMDA\",\"transDate\":\"20171126\",\"transTime\":\"20171126111304888\",\"inExtData\":\"测试请求扩展大字段\"}";
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


        System.out.println(stringResponseEntity);


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
     * 支付宝服务窗
     */
    @Test
    public void H5_ZFBJSAPI(){
        String context="{\"platformId\":\"A00012017060000000691\",\"merchantNo\":\"M29002017110000030909\",\"merchantSeq\":\"A000120170600000006912017112621\",\"mchSeqNo\":\"11\",\"selectTradeType\":\"H5_ZFBJSAPI\",\"amount\":\"1\",\"orderInfo\":\"统一下单DEMO-H5_ZFBJSAPI\",\"notifyUrl\":\"https://wxpay.cmbc.com.cn/cmbcpaydemo/NoticeServlet?name=notice\",\"remark\":\"MTQxMDAwMDAwMDAwMDAwMDA=\",\"transDate\":\"20171126\",\"transTime\":\"20171126111304888\",\"inExtData\":\"测试请求扩展大字段\",\"userId\":\"2088102170360594\"}";
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


        System.out.println(stringResponseEntity);


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
     * 民生反扫
     */
    @Test
    public void API_CMBCSCAN(){
        String context="{\"platformId\":\"A00012017060000000691\",\"merchantNo\":\"M29002017110000030909\",\"merchantSeq\":\"A00012017050000000545T13125\",\"mchSeqNo\":\"11\",\"selectTradeType\":\"API_CMBCSCAN\",\"amount\":\"1\",\"orderInfo\":\"统一下单DEMO-API_CMBCSCAN\",\"notifyUrl\":\"https://wxpay.cmbc.com.cn/cmbcpaydemo/NoticeServlet?name=notice\",\"remark\":\"MTQwMDAwMDAwMDAwMDAwMDAw\",\"transDate\":\"20171126\",\"transTime\":\"20171126120504985\",\"inExtData\":\"测试请求扩展大字段\"}";
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


        System.out.println(stringResponseEntity);


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
     * 支付结果查询
     */
    @Test
    public void QUERY(){
        String context="{\"platformId\":\"A00012017060000000691\",\"merchantNo\":\"M29002017110000030955\",\"merchantSeq\":\"M2900201711000003095504\",\"tradeType\":\"1\",\"orgvoucherNo\":\"10862016070514230500\",\"reserve\":\"查询支付或查询退款\"}";
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



        ResponseEntity<HashMap> stringResponseEntity = restTemplate.postForEntity("http://wxpay.cmbc.com.cn:1080/mobilePlatform/appserver/paymentResultSelect.do", data, HashMap.class);


        System.out.println(stringResponseEntity);


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
     * 退款A000120170600000006912017112804
     */
    @Test
    public void CANCEL(){
        String context="{\"platformId\":\"A00012017060000000691\",\"merchantNo\":\"M29002017110000030955\",\"merchantSeq\":\"M2900201711000003095503\",\"mchSeqNo\":\"11\",\"orderAmount\":\"1\",\"orderNote\":\"退款\",\"reserve\":\"下错单了\"}";
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


        System.out.println(stringResponseEntity);


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
        String context="{\"merchantNo\":\"M29002017110000030912\",\"platformId\":\"A00012017060000000691\",\"tradeAmount\":\"1\",\"tradeNote\":\"\"}";
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


        System.out.println(stringResponseEntity);


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
     *商户提现信息查询
     */
    @Test
    public void wddpQuery(){
        String context="{\"merchantNo\":\"M29002017110000030912\",\"platformId\":\"A00012017060000000691\",\"tradeAmount\":\"10\",\"tradeNote\":\"zzzzzzz\"}";
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


        System.out.println(stringResponseEntity);


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
