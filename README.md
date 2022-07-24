# security-cas-spring-boot-starter
security starter for spring boot

### 说明


 > 基于 Security 的 Spring Boot Starter 实现

### Maven

``` xml
<dependency>
	<groupId>${project.groupId}</groupId>
	<artifactId>security-cas-spring-boot-starter</artifactId>
	<version>2.0.0.RELEASE</version>
</dependency>
```


### 配置参考

> application.yml

```yaml
spring:
  # 权限控制
  security:
    # 默认路径拦截规则定义
    filter-chain-definition-map:
      '[/]': anon
      '[/**/favicon.ico]': anon
      '[/webjars/**]': anon
      '[/assets/**]': anon
      '[/error*]': anon
      '[/logo/**]': anon
      '[/swagger-ui.html**]': anon
      '[/swagger-resources/**]': anon
      '[/doc.html]': anon
      '[/bycdao-ui/**]': anon
      '[/v2/**]': anon
      '[/v2/api-docs]': anon
      '[/kaptcha*]': anon
      '[/actuator*]': anon
      '[/actuator/**]': anon
      '[/authz/qrcode/info]': anon
      '[/authz/qrcode/bind]': anon
      '[/authz/login/code2Session]': anon
      '[/authz/login/refershJwt]': anon
      '[/authz/userRelation/newOrrenew]': anon
      '[/authz/logout]': anon
      '[/druid/*]': ipaddr[192.168.1.0/24]
      '[/monitoring]': roles[admin]
      '[/monitoring2]': roles[1,admin]
      '[/monitoring3]': perms[1,admin]
      '[/monitoring4]': perms[1]
    # Cas 单点认证登录
    cas:
      enabled: true
      authc:
        path-pattern: /authz/login/cas
        accept-any-proxy: true
        attributes:
        - comsys_department
        - comsys_post
        - comsys_cardid
        - comsys_post_type
        - comsys_educational
        - comsys_phone
        - comsys_genders
        - comsys_name
        - comsys_loginid
        - comsys_email
        - comsys_role
        - comsys_other_post
        - comsys_usertype
        - comsys_teaching_number
        continue-chain-before-successful-authentication: false
        frontend-proxy: true
        frontend-target-url: http://10.30.186.134:8089/#/client
        always-use-default-target-url: true
        default-target-url: /portal  
        gateway: false
        login-url: http://10.30.186.104/sso/login
        logout-url: http://10.30.186.104/sso/logout
        prefix-url: http://10.30.186.104/sso/
        protocol: cas20-proxy
        proxy-receptor-url: /authz/login/cas-proxy
        proxy-callback-url: http://10.30.186.134:8080/smartedu-authz/authz/login/cas-proxy
        renew: false
        service-url: http://10.30.186.134:8080/smartedu-authz/authz/login/cas
        service-callback-url: http://10.30.186.134:8080/smartedu-authz/authz/login/cas
        session-mgt:
          allow-session-creation: true
          creation-policy: if-required
```	    
