package com.microsoft.sample.security.servlet;

import javax.servlet.Filter;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

@Configuration
@ConditionalOnClass(FilterRegistrationBean.class)
@ConditionalOnBean(AzureContainerAppsCertificateFilter.class)
public class FilterRegistrationBeanConfig {

    @Bean
    FilterRegistrationBean<Filter> clientCertificateMapperFilterRegistrationBean(AzureContainerAppsCertificateFilter filter) {
        FilterRegistrationBean<Filter> result = new FilterRegistrationBean<>(filter);
        result.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return result;
    }
}
