package com.pamesh.security.util;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Base64Utils;
import org.springframework.util.FileCopyUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;

/**
 * The Class JwtUtil.
 *
 * Library used : https://github.com/jwtk/jjwt#install-jdk-maven
 * 
 * @author Pamesh Bansal
 */
public class JwtUtil {

    

    /** The Constant LOGGER. */
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtUtil.class);

    /** The Constant NEW_LINES_PATTERN. */
    private static final String NEW_LINES_PATTERN = "\\r\\n|\\r|\\n";

    /** The private key. */
    private PrivateKey privateKey;
    
    /** The public key. */
    private PublicKey publicKey;

    /**
     * Instantiates a new jwt util.
     *
     * @param resourceLoader the resource loader
     * @param privateKeyUrl the private key url
     * @param publicKeyUrl the public key url
     */
    public JwtUtil(ResourceLoader resourceLoader, String privateKeyUrl, String publicKeyUrl) {
        Resource privateKeyResource = resourceLoader.getResource(privateKeyUrl);
        String privateKey = loadResource(privateKeyResource);
        Resource publicKeyResource = resourceLoader.getResource(publicKeyUrl);
        String publicKey = loadResource(publicKeyResource);
        convertToKeyPair(privateKey, publicKey);
    }

  /**
   * Generate JWT.
   *
   * @param userName the user name
   * @param roles the roles
   * @return the string
   */
  //@formatter:off
    public String generateJWT(String userName, Collection<GrantedAuthority> roles) {

        ZonedDateTime currentTime =LocalDateTime.now().atZone(ZoneId.systemDefault());
        String rolesString = roles.stream().map(e->e.getAuthority()).collect(Collectors.joining(","));
        String jwt = Jwts.builder()
                .setSubject(userName)
                .setIssuedAt(Date.from(currentTime.toInstant()))
                .claim("roles", rolesString)
                .setExpiration(Date.from(currentTime.plusMinutes(5).toInstant()))
                .setId(UUID.randomUUID().toString())
                .signWith(privateKey)
                .compact();

        LOGGER.info("JWT generated {}", jwt);
        return jwt;
    }
  //@formatter:on

    /**
   * Parses the JWT.
   *
   * @param token the token
   * @return the claims
   */
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

    /**
     * Load resource.
     *
     * @param resource the resource
     * @return the string
     */
    public String loadResource(Resource resource) {
        try {
            InputStream inputStream = resource.getInputStream();
            byte[] fileBytes = FileCopyUtils.copyToByteArray(inputStream);
            return new String(fileBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            LOGGER.error("Error in loading resource file ", e);
            throw new IllegalStateException(e);
        }
    }

    /**
     * Convert to key pair.
     *
     * @param privateKey the private key
     * @param publicKey the public key
     */
    public void convertToKeyPair(String privateKey, String publicKey) {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");

            publicKey = publicKey.replaceAll(NEW_LINES_PATTERN, "")
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "");

            byte[] b = Base64Utils.decodeFromString(publicKey);
            X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(b);
            this.publicKey = kf.generatePublic(keySpecX509);

            privateKey = privateKey.replaceAll(NEW_LINES_PATTERN, "")
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "");
            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey.getBytes()));
            this.privateKey = kf.generatePrivate(keySpecPKCS8);

        } catch (Exception e) {
            LOGGER.error("Error converting string to key specs ", e);
            throw new IllegalStateException(e);
        }
    }

}
