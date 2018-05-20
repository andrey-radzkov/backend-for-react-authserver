package com.radzkov.authserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import java.security.KeyPair;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.springframework.security.oauth2.provider.token.AccessTokenConverter.AUD;
import static org.springframework.security.oauth2.provider.token.AccessTokenConverter.AUTHORITIES;
import static org.springframework.security.oauth2.provider.token.AccessTokenConverter.CLIENT_ID;
import static org.springframework.security.oauth2.provider.token.AccessTokenConverter.EXP;
import static org.springframework.security.oauth2.provider.token.AccessTokenConverter.GRANT_TYPE;
import static org.springframework.security.oauth2.provider.token.AccessTokenConverter.JTI;
import static org.springframework.security.oauth2.provider.token.AccessTokenConverter.SCOPE;
import static org.springframework.security.oauth2.provider.token.UserAuthenticationConverter.USERNAME;

@SpringBootApplication
@Controller
@SessionAttributes("authorizationRequest")
@EnableResourceServer
public class AuthserverApplication extends WebMvcConfigurerAdapter {

    private static final String ACME = "acme";
    @Value("#{'${allowed.domains}'.split(',')}")
    private String[] allowedDomains;

    @Autowired
    private JwtAccessTokenConverter jwtAccessTokenConverter;


    public static void main(String[] args) {

        SpringApplication.run(AuthserverApplication.class, args);
    }

    @RequestMapping("/user")
    @ResponseBody
    public Principal user(Principal user) {

        return user;
    }

    @PostMapping("/vk-auth")
    @ResponseBody
    public OAuth2AccessToken vkAuth(@RequestBody Token vkToken) {
        //TODO: refactor
        //TODO: use http://www.baeldung.com/spring-security-oauth-jwt
        UserInfoTokenServices userInfoTokenServices = new UserInfoTokenServices(
                "https://api.vk.com/method/users.get?v=5.75&user_ids=" + vkToken.getUserId() +
                        "&access_token=" + vkToken.getToken(), "6483319");
        OAuth2Authentication vkAuthentication = userInfoTokenServices.loadAuthentication(vkToken.getToken());
        Map<String, Object> response = ((ArrayList<HashMap<String, Object>>) ((HashMap<String, Object>) vkAuthentication.getUserAuthentication().getDetails()).get("response")).get(0);
        String name = response.get("id") + " " + response.get("first_name") + " " + response.get("last_name");

        Map<String, Object> map = new HashMap<>();
        map.put(CLIENT_ID, ACME);
        map.put(GRANT_TYPE, "access_token");
        map.put(CLIENT_ID, ACME);
        map.put(CLIENT_ID, ACME);
        map.put(USERNAME, name);
        map.put(AUTHORITIES, "ROLE_USER,ROLE_ACTUATOR");
        map.put(SCOPE, Collections.singletonList("resource-read"));
        map.put(SCOPE, Collections.singletonList("resource-read"));
        map.put(AUD, Arrays.asList("resource-id1", "resource-id2"));

        OAuth2Authentication oAuth2Authentication = jwtAccessTokenConverter.extractAuthentication(map);


        DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("access");
        HashMap<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put(SCOPE, Collections.singletonList("resource-read"));
        additionalInformation.put(JTI, UUID.randomUUID().toString());
        additionalInformation.put(EXP, new Date(new Date().getTime() + (5 * 60000)));

        accessToken.setAdditionalInformation(additionalInformation);

        accessToken.setRefreshToken(new DefaultOAuth2RefreshToken("refresh"));
        return jwtAccessTokenConverter.enhance(accessToken, oAuth2Authentication);
    }

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {

        registry.addViewController("/login").setViewName("login");
        registry.addViewController("/oauth/confirm_access").setViewName("authorize");
    }

//    @Bean
//    public FilterRegistrationBean someFilterRegistration() {
//
//        FilterRegistrationBean registration = new FilterRegistrationBean();
//        registration.setOrder(1);
//        return registration;
//    }

    @Configuration
    @Order(-20)
    protected static class LoginConfig extends WebSecurityConfigurerAdapter {


        @Autowired
        private AuthenticationManager authenticationManager;

        @Override
        public void configure(WebSecurity web) throws Exception {

            web.ignoring().mvcMatchers("/oauth/check_token", "/oauth/token_key", "/vk-auth");
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http
                    .antMatcher("/**")
                    .authorizeRequests()
                    .antMatchers("/vk-auth**")
                    .permitAll().and().formLogin().loginPage("/login").permitAll()
                    .and()
                    .requestMatchers()
                    .antMatchers("/login", "/oauth/authorize"
                            , "/oauth/confirm_access", "/check_token", "/token_key"
                            , "/oauth/check_token", "/oauth/token_key")
                    .and()
                    .authorizeRequests().anyRequest().authenticated().and();
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {

            auth.parentAuthenticationManager(authenticationManager);
        }
    }

    @Configuration
    @EnableAuthorizationServer
    protected class OAuth2AuthorizationConfig extends
            AuthorizationServerConfigurerAdapter {

        @Autowired
        private AuthenticationManager authenticationManager;

        @Bean
        public JwtAccessTokenConverter jwtAccessTokenConverter() {

            JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
            KeyPair keyPair = new KeyStoreKeyFactory(
                    new ClassPathResource("keystore.jks"), "foobar".toCharArray())
                    .getKeyPair("test");
            //new String(Base64.encode(keyPair.getPublic().getEncoded())) //public key generation
            converter.setKeyPair(keyPair);
            return converter;
        }


        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

            clients.inMemory()
                    .withClient(ACME)
                    .secret("acmesecret")
                    .autoApprove(false)
                    .accessTokenValiditySeconds(300)
                    // OPTIONAL in specification!!!!!
                    .redirectUris(allowedDomains)
                    .authorizedGrantTypes("authorization_code", "implicit", "refresh_token", "password")
                    .scopes("resource-read", "write")
                    .resourceIds("resource-id1", "resource-id2")
                    .and().withClient("acme2")
                    .secret("acmesecret2")
                    .autoApprove(false)
                    .accessTokenValiditySeconds(300)
                    .authorizedGrantTypes("authorization_code", "implicit", "refresh_token", "password")
                    .scopes("resource-read", "write")
                    .resourceIds("resource-id2")
            ;
        }

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints)
                throws Exception {

            endpoints.authenticationManager(authenticationManager)
                    .accessTokenConverter(jwtAccessTokenConverter());
        }

        @Override
        public void configure(AuthorizationServerSecurityConfigurer oauthServer)
                throws Exception {

            oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess(
                    "permitAll()");
        }

    }
}
