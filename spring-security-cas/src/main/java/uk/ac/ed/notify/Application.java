package uk.ac.ed.notify;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.velocity.VelocityAutoConfiguration;
import org.springframework.boot.context.embedded.ConfigurableEmbeddedServletContainer;
import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.context.embedded.ErrorPage;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.web.SpringBootServletInitializer;
import org.springframework.boot.orm.jpa.EntityScan;
import org.springframework.cloud.security.oauth2.resource.EnableOAuth2Resource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpStatus;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;
import uk.ac.ed.notify.config.RemoteUserAuthenticationFilter;
import uk.ac.ed.notify.repository.UiUserRepository;
import uk.ac.ed.notify.service.UiUserDetailsService;

/**
 * Created by rgood on 18/09/2015.
 */
@SpringBootApplication
@EntityScan("uk.ac.ed.notify")
@ComponentScan({"uk.ac.ed.notify"})
@EnableOAuth2Resource
// Prevents ClassNotFoundException: org.apache.velocity.runtime.log.CommonsLogLogChute
// https://stackoverflow.com/questions/32067759/spring-boot-starter-cache-velocity-is-missing
@EnableAutoConfiguration(exclude = VelocityAutoConfiguration.class)
public class Application extends SpringBootServletInitializer {

    @Value("${java.naming.ldap.derefAliases}")
    String derefAliases;

    @Value("${cas.serviceUrl:http://localhost:8081/login/cas}") // Endpoint in this app
    private String casServiceUrl;

    @Value("${cas.protocol:http}")
    private String casProtocol;

    @Value("${cas.server:localhost:8080}")
    private String casServer;

    @Value("${cas.context:/cas}")
    private String casContext;

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    /*
     * Optional CAS Authentication
     *
     * See https://www.baeldung.com/spring-security-cas-sso
     */

    public String casLoginUrl() {
        return casProtocol + "://" + casServer + casContext + "/login";
    }

    @Bean
    public ServiceProperties serviceProperties() {
        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setService(casServiceUrl);
        serviceProperties.setSendRenew(false);
        return serviceProperties;
    }

    @Bean
    @Primary
    public AuthenticationEntryPoint authenticationEntryPoint(ServiceProperties sP) {
        CasAuthenticationEntryPoint entryPoint = new CasAuthenticationEntryPoint();
        entryPoint.setLoginUrl(casLoginUrl());
        entryPoint.setServiceProperties(sP);
        return entryPoint;
    }

    @Bean
    public TicketValidator ticketValidator() {
        return new Cas20ServiceTicketValidator(casProtocol + "://" + casServer + casContext);
    }

    @Bean
    public CasAuthenticationProvider casAuthenticationProvider() {
        CasAuthenticationProvider provider = new CasAuthenticationProvider();
        provider.setServiceProperties(serviceProperties());
        provider.setTicketValidator(ticketValidator());
        provider.setUserDetailsService(
                s -> new User("casuser", "Mellon", true, true, true, true,
                        AuthorityUtils.createAuthorityList("ROLE_ADMIN")));
        provider.setKey("CAS_PROVIDER_LOCALHOST_9000");
        return provider;
    }

    @Configuration
    @EnableWebSecurity
    protected static class LoginConfig extends WebSecurityConfigurerAdapter {

        @Autowired
        private AuthenticationManager authenticationManager;

        @Autowired
        UiUserRepository uiUserRepository;

        @Autowired
        private ServiceProperties serviceProperties;

        @Autowired
        private CasAuthenticationProvider casAuthenticationProvider;

        @Autowired
        private AuthenticationEntryPoint authenticationEntryPoint;

//        @Override
//        protected void configure(HttpSecurity http) throws Exception {
//            http.addFilterBefore(remoteUserAuthenticationFilter(), RequestHeaderAuthenticationFilter.class)
//                    .authenticationProvider(preauthAuthProvider())
//                    .csrf().disable()
//                    .authorizeRequests().anyRequest().authenticated()
//                    .antMatchers("/office365NewEmailCallback/**").permitAll()
//                    .antMatchers("/healthcheck/**").permitAll()
//                    .antMatchers("/scheduled-tasks", "/publishers", "/subscribers", "/topic-subscriptions/**").hasRole("SYSSUPPORT")
//                    .antMatchers("/topic/**").hasRole("USRSUPPORT")
//                    .antMatchers("/").hasRole("GROUP")
//                    .and()
//                    .httpBasic()
//                    .authenticationEntryPoint(authenticationEntryPoint);;
//        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .httpBasic()
                    .authenticationEntryPoint(authenticationEntryPoint)
                    .and()
                    .addFilterBefore(remoteUserAuthenticationFilter(), RequestHeaderAuthenticationFilter.class)
                    .addFilterBefore(casAuthenticationFilter(), RequestHeaderAuthenticationFilter.class)
                    .csrf().disable()
                    .authorizeRequests().anyRequest().authenticated()
                    .antMatchers("/office365NewEmailCallback/**").permitAll()
                    .antMatchers("/healthcheck/**").permitAll()
                    .antMatchers("/scheduled-tasks", "/publishers", "/subscribers", "/topic-subscriptions/**").hasRole("SYSSUPPORT")
                    .antMatchers("/topic/**").hasRole("USRSUPPORT")
                    .antMatchers("/").hasRole("GROUP");
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) {
            auth.authenticationProvider(casAuthenticationProvider)
                    .authenticationProvider(preauthAuthProvider())
                    .parentAuthenticationManager(authenticationManager);
        }

        @Override
        protected AuthenticationManager authenticationManager() {
            return new ProviderManager(Arrays.asList(preauthAuthProvider(), casAuthenticationProvider));
        }

        @Bean
        public UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> userDetailsServiceWrapper() {
            UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> wrapper =
                    new UserDetailsByNameServiceWrapper<>();
            wrapper.setUserDetailsService(new UiUserDetailsService(uiUserRepository));
            return wrapper;
        }

        @Bean
        public PreAuthenticatedAuthenticationProvider preauthAuthProvider() {
            PreAuthenticatedAuthenticationProvider preauthAuthProvider =
                    new PreAuthenticatedAuthenticationProvider();
            preauthAuthProvider.setPreAuthenticatedUserDetailsService(userDetailsServiceWrapper());
            return preauthAuthProvider;
        }

        @Bean
        public RemoteUserAuthenticationFilter remoteUserAuthenticationFilter() {
            RemoteUserAuthenticationFilter filter = new RemoteUserAuthenticationFilter();
            filter.setAuthenticationManager(authenticationManager());
            return filter;
        }

        @Bean
        public CasAuthenticationFilter casAuthenticationFilter() {
            CasAuthenticationFilter filter = new CasAuthenticationFilter();
            filter.setServiceProperties(serviceProperties);
            filter.setAuthenticationManager(authenticationManager());
            return filter;
        }

    }

    @Bean
    @ConfigurationProperties(prefix="ldap.contextSource")
    public LdapContextSource contextSource() {
        LdapContextSource contextSource = new LdapContextSource();
        Map<String,Object> baseEnvironmentProperties = new HashMap<>();
        baseEnvironmentProperties.put("java.naming.ldap.derefAliases", derefAliases);
        contextSource.setBaseEnvironmentProperties(baseEnvironmentProperties);
        return contextSource;
    }

    @Bean
    public LdapTemplate ldapTemplate(ContextSource contextSource) {
        return new LdapTemplate(contextSource);
    }    
    
    
    /* */
    @Bean
    public EmbeddedServletContainerCustomizer containerCustomizer() {

        return new EmbeddedServletContainerCustomizer() {
            @Override
            public void customize(ConfigurableEmbeddedServletContainer container) {

                ErrorPage error401Page = new ErrorPage(HttpStatus.UNAUTHORIZED, "/error.html");
                ErrorPage error404Page = new ErrorPage(HttpStatus.NOT_FOUND, "/error.html");
                ErrorPage error500Page = new ErrorPage(HttpStatus.INTERNAL_SERVER_ERROR, "/error.html");

                container.addErrorPages(error401Page, error404Page, error500Page);
            }
        };
    }
   
    
}

