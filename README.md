# security-cas-spring-boot-starter

### 组件简介

> 基于 spring-security-cas、cas-client 的 Spring Boot Starter 实现

主要实现 Security + cas-client 与Spring Boot的整合，实现通过yaml配置即可实现权限拦截扩展，实现基于Cas单点登录的快速接入

### 使用说明

##### 1、Spring Boot 项目添加 Maven 依赖

``` xml
<dependency>
	<groupId>com.github.hiwepy</groupId>
	<artifactId>security-cas-spring-boot-starter</artifactId>
	<version>${project.version}</version>
</dependency>
```

##### 2、在`application.yml`文件中增加如下配置

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
        frontend-target-url: http://127.0.0.1:8089/#/client
        always-use-default-target-url: true
        default-target-url: /portal
        gateway: false
        login-url: http://127.0.0.1/sso/login
        logout-url: http://127.0.0.1/sso/logout
        prefix-url: http://127.0.0.1/sso/
        protocol: cas20-proxy
        proxy-receptor-url: /authz/login/cas-proxy
        proxy-callback-url: http://127.0.0.1:8080/smartedu-authz/authz/login/cas-proxy
        renew: false
        service-url: http://127.0.0.1:8080/smartedu-authz/authz/login/cas
        service-callback-url: http://127.0.0.1:8080/smartedu-authz/authz/login/cas
        session-mgt:
          allow-session-creation: true
          creation-policy: if-required
```

##### 3、使用示例

```java
 SecurityPrincipal principal = SubjectUtils.getPrincipal(SecurityPrincipal.class);
```

## Jeebiz 技术社区

Jeebiz 技术社区 **微信公共号**、**小程序**，欢迎关注反馈意见和一起交流，关注公众号回复「Jeebiz」拉你入群。

|公共号|小程序|
|---|---|
| ![](https://raw.githubusercontent.com/hiwepy/static/main/images/qrcode_for_gh_1d965ea2dfd1_344.jpg)| ![](https://raw.githubusercontent.com/hiwepy/static/main/images/gh_09d7d00da63e_344.jpg)|

