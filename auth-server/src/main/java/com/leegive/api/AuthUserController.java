package com.leegive.api;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * Created by leegive on 07/10/2016.
 */
@RestController
@RequestMapping("/")
public class AuthUserController {

    @RequestMapping("/me")
    public Principal getCurrentLoggedInUser(Principal user) {
        return user;
    }

}
