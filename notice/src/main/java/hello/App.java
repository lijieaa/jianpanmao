package hello;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Created by Administrator on 2017/11/27.
 */
@SpringBootApplication
@Controller
public class App {

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }

    @RequestMapping("/")
    public void acceptNoticeContext(HttpServletRequest request, HttpServletResponse response) {
        try {
            // 接收异步通知的关键代码
            StringBuffer noticeContext = new StringBuffer();
            BufferedReader reader = request.getReader();
            String data = null;
            while ((data = reader.readLine()) != null) {
                noticeContext.append(data);
            }
            // 给通知返回结果的输出流
            PrintWriter out = response.getWriter();
            // 此处对通知密文进行解密，通过后返回字符串”SUCCESS”，否则返回”E”

            out.print("SUCCESS");
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
