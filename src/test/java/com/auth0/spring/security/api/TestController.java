package com.auth0.spring.security.api;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class TestController {

    @RequestMapping(value = "secured")
    @ResponseBody
    public String secured() {
        return "Bravo you have accessed a secured url!";
    }

    @RequestMapping(value = "unsecured")
    @ResponseBody
    public String unsecured() {
        return "This is an unsecured url";
    }

}
