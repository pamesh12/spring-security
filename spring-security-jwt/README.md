- [Secure REST API with JWT using Spring Security](#secure-rest-api-with-jwt-using-spring-security)
  * [What is JSON Web Token?](#what-is-json-web-token)
  * [Application Flow](#application-flow)
  * [Maven Dependencies](#maven-dependencies)
  * [Rest API](#rest-api)
  * [Initializing DB](#initializing-db)
  * [Securing API](#securing-api)
    + [User Login Flow](#user-login-flow)
    + [API Flow](#api-flow)
  * [JWT](#jwt)
    + [Generate JWT](#generate-jwt)
    + [Validate JWT](#validate-jwt)
  * [Build Application](#build-application)
  * [Run Application](#run-application)
  * [Test Application](#test-application)

# Secure REST API with JWT using Spring Security

In this post, we will learn how to handle authentication and authorization on  _RESTful APIs_  written with  _Spring Boot_  and secured with _Spring Security_  and  _JWTS_ .

## What is JSON Web Token?

JSON Web Token (JWT) is an open standard ([RFC 7519](https://tools.ietf.org/html/rfc7519)) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed. JWTs can be signed using a secret (with the **HMAC**  algorithm) or a public/private key pair using **RSA** or **ECDSA**.

## Application Flow
The flow for the application can be designated as the following steps.

 - Get the JWT based token from the authentication endpoint using the
    credentials provided by the service provider, eg `/login`.
 -  Extract token from the authentication result.
 -  Set the HTTP header  `Authorization` value as `Bearer <jwt_token>`.
 -  Then send a request to access the protected resources.
 -  If the requested resource is protected, Spring Security will use our custom `Filter` to validate the JWT token, and build an `Authentication` object and set it in Spring Security specific `SecurityContextHolder` to complete the authentication progress. The following list shows the validation steps done in :
	-	Check that the JWT is well formed
   	-	Check the signature
   	-	Validate the standard claims
   	-	Check the Client permissions (scopes)
 - If the JWT token is valid it will return the requested resource to client.

## Maven Dependencies
Below dependencies will be required for the project

````java
<!--Spring Web -->
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-web</artifactId>
</dependency>

<!--Spring security -->
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-security</artifactId>
</dependency>

<!--Spring Data -->
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
<dependency>
	<groupId>com.h2database</groupId>
	<artifactId>h2</artifactId>
	<scope>runtime</scope>
</dependency>

<!-- JWT dependencies start -->
<dependency>
	<groupId>io.jsonwebtoken</groupId>
	<artifactId>jjwt-api</artifactId>
	<version>${jwt.version}</version>
</dependency>
<dependency>
	<groupId>io.jsonwebtoken</groupId>
	<artifactId>jjwt-impl</artifactId>
	<version>${jwt.version}</version>
	<scope>runtime</scope>
</dependency>
<dependency>
	<groupId>io.jsonwebtoken</groupId>
	<artifactId>jjwt-jackson</artifactId> 
	<version>${jwt.version}</version>
	<scope>runtime</scope>
</dependency>
<!-- JWT dependencies end-->
````

## Rest API
We will expose `/hello` API in this project.
````java
 @GetMapping("/hello")
 @PreAuthorize("hasPermission('object','admin')")
 public ResponseEntity<String> user(){
     Authentication auth =  SecurityContextHolder.getContext().getAuthentication();
     return new ResponseEntity<>("Hello "+ auth.getPrincipal(), HttpStatus.OK);
 }
````

## Initializing DB

We will be initializing DB with data at server startup using `CommandLineRunner`. H2 DB is used for the project for simplicity.

````java
@SpringBootApplication
@EnableAutoConfiguration(exclude = {ErrorMvcAutoConfiguration.class})
public class SpringSecurityJwtApplication implements CommandLineRunner {
     @Autowired
     UserService userService;
    /**
     * The main method.
     * @param args the arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityJwtApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        userService.saveUser();
    }
}
````

## Securing API
### User Login Flow
User need to send the `/login` request to generate the JWT token. 

`UserAuthenticationFilter` extending `UsernamePasswordAuthenticationFilter` is added to handle login request.

````java
 public UserAuthenticationFilter userAuthenticationFilter() throws Exception {
    UserAuthenticationFilter filter = new UserAuthenticationFilter(authenticationManager(), userAuthenticationSuccessHandler(), mapper());
    filter.setAuthenticationFailureHandler(failureHandler(restAuthenticationEntryPoint()));
    return filter;
}
 @Bean
public FilterRegistrationBean<UserAuthenticationFilter> userAuthFilter() throws Exception {
    final FilterRegistrationBean<UserAuthenticationFilter> registrationBean = new FilterRegistrationBean<>();
    registrationBean.setFilter(userAuthenticationFilter());
    /*
     * Normally the filter is called twice, one invocation is by servlet container and the other is by
     * Spring Security, So by adding this line in the filter bean implementation make sure that it is
     * not registered in servlet. Filter will be added only in spring security calls for token.
     */
    registrationBean.setEnabled(false);
    return registrationBean;
}

Filter is added to security config as below:
http.addFilterAt(userAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class) //Add filter for user login
````

`UserAuthenticationProvider` is added to authenticate the request against the details from DB.
````java
 @Bean
public UserAuthenticationProvider userAuthenticationProvider() {
    return new UserAuthenticationProvider();
}
```` 

* `attemptAuthentication`: where we parse the user's credentials and issue them to the  `AuthenticationManager`
* `UserAuthenticationSuccessHandler`: which is called when a user successfully logs in. We use this method to [generate](#generate-jwt) a JWT for this user.

**Request**
||  |
|----------|--|
|Url        | /login |
|Method     | POST |
|Content-Type| application/json |
|Body| {"userName" : "{userName}","password" : {password}"}|

**Response:** 
| Status Code       | Response           |
| ------------- |:-------------:|
| 200 | JWT token is sent back in response| 
| 401 | Credentials provided are invalid.      |
| 405 | Method not supported.      |

### API Flow
For JWT validation, add a filter to Spring security filter chain.

````java
public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
    List<String> ignorePaths = new ArrayList<>();
    ignorePaths.add("/login"); // ignore login
    ignorePaths.add("/h2-console/**"); //ignore h2-console url's
    return new JwtAuthenticationFilter(authenticationManager(), ignorePaths);
}
````

Filter will check for `Authorization` header in the request. If header is available, request is forwarded to `AuthenticationProvider` after creating `JwtAuthenticationToken` with token value.
````java
String jwtBearerToken = request.getHeader(HttpHeaders.AUTHORIZATION);
if (StringUtils.hasText(jwtBearerToken)) {
	JwtAuthenticationToken token = JwtAuthenticationToken.builder().bearerToken(jwtBearerToken).build();
}
````

Add an implementation of `AuthenticationProvider` for validation of JWT. 
````java
@Bean
public JwtAuthenticationProvider jwtAuthenticationProvider() {
    return new JwtAuthenticationProvider();
}
````
`JwtAuthenticationProvider` has been added  to support `JwtAuthenticationToken`

````java
JwtAuthenticationProvider.java
@Override
public boolean supports(Class<?> authentication) {
    return JwtAuthenticationToken.class.isAssignableFrom(authentication);
}
````

`JwtAuthenticationProvider`  [validates](#validate-jwt) the passed JWT . If successful, this provider adds the user details to security context.
````java
if(jwt != null) {
   List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(String.valueOf(jwt.get("roles")));
   return new UsernamePasswordAuthenticationToken(jwt.getSubject(), "", authorities);
}
````

## JWT
We will be using RSA Key Pair for JWT generation and verification.
Algorithm : RS256
* Private key will be used to sign the token.
* Public Key will be used to verify the token and claims.

We are using [jjwt](https://github.com/jwtk/jjwt#install-jdk-maven) library for JWT.

### Generate JWT 
 
 We are storing userName and user roles in the token generated. 
  ````java
public String generateJWT(String userName, Collection<GrantedAuthority> roles) {
		ZonedDateTime currentTime =LocalDateTime.now().atZone(ZoneId.systemDefault()); //current time
	 String rolesString = roles.stream().map(e->e.getAuthority()).collect(Collectors.joining(",")); //Get all the roles
	 String jwt = Jwts.builder()
	         .setSubject(userName) //Set username as subject
	         .setIssuedAt(Date.from(currentTime.toInstant())) //Set issue time
	         .claim("roles", rolesString) //set claims
	         .setExpiration(Date.from(currentTime.plusMinutes(5).toInstant())) //Expiration of JWT
	         .setId(UUID.randomUUID().toString())
	         .signWith(privateKey) //Sign with private key
	         .compact();
	 LOGGER.info("JWT generated {}", jwt);
	 return jwt;
 }
````

### Validate JWT
Code to parse JWT. 
````java
public Claims parseJWT(String token) {
 try {
     Jwt<?, Claims> jwt = Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(token);
     LOGGER.info("JWT parsed {}", jwt);
     return jwt.getBody();
 } catch (Exception e) {
     LOGGER.error("Error in validating JWT token {}", e);
 }
 return null;
}
````

## Build Application

To build application, run below command  
`mvn clean install`

## Run Application
Execute below command to run the application  
`java -jar spring-security-jwt-1.0.0.jar`

## Test Application
* Execute login request.  
`curl --location --request POST 'localhost:8080/login' \
--header 'Content-Type: application/json' \
--data-raw '{
	"userName": "admin",
	"password" : "password"
}'
`
If request is success, token will be given in response header.

* Execute `/hello` endpoint with jwt header.  
`curl --location --request GET 'localhost:8080/hello' \
--header 'Authorization: Bearer <jwt-token>'`

