package com.certmgmt.config;

import com.certmgmt.web.CorsFilter;
import com.certmgmt.web.JwtAuthFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

@Configuration
public class WebConfig {

    @Bean
    public FilterRegistrationBean<CorsFilter> corsFilter() {
        FilterRegistrationBean<CorsFilter> reg = new FilterRegistrationBean<>(new CorsFilter());
        reg.addUrlPatterns("/*");
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return reg;
    }

    @Bean
    public FilterRegistrationBean<JwtAuthFilter> jwtAuthFilter(Env env, ObjectMapper objectMapper) {
        FilterRegistrationBean<JwtAuthFilter> reg =
                new FilterRegistrationBean<>(new JwtAuthFilter(env, objectMapper));
        reg.addUrlPatterns("/*");
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        return reg;
    }
}
