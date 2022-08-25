package yang.practice.springsecuritydemo.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class JwtUtil {

    private final String SECRET_KEY = "secret";

    public String extractUsername(DecodedJWT token) {
        return token.getSubject();
    }

    public Date extractExpiration(DecodedJWT token) {
        return token.getExpiresAt();
    }

    public String generateToken(JWTCreator.Builder builder, String username) {
        // the builder has withClaim
        return createToken(builder, username);
    }

    public String generateToken(JWTCreator.Builder builder, String username, Date expiresAt) {
        // the builder has withClaim
        return createToken(builder, username, expiresAt);
    }

    public String generateToken(String username) {
        return createToken(username);
    }

    public DecodedJWT decodeToken(String authorizationHeader) {
        String token = authorizationHeader.substring("Bearer ".length());
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
        JWTVerifier verifier = JWT.require(algorithm).build();
        return verifier.verify(token);
    }

    public Boolean validateToken(DecodedJWT token) {
        return this.extractUsername(token) != null && !this.isTokenExpired(token);
    }

    private String createToken(String subject) {
        Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY.getBytes());
        return JWT.create()
                .withSubject(subject)
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000)) // 10min
                .sign(algorithm);
    }


    private String createToken(JWTCreator.Builder builder, String subject) {
        Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY.getBytes());
        return builder
                .withSubject(subject)
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000)) // 10min
                .sign(algorithm);
    }

    private String createToken(JWTCreator.Builder builder, String subject, Date expiresAt) {
        Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY.getBytes());
        return builder
                .withSubject(subject)
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .withExpiresAt(expiresAt)
                .sign(algorithm);
    }



    private Boolean isTokenExpired(DecodedJWT token) {
        // 如果失效時間是在目前時間之前，表示失效
        return extractExpiration(token).before(new Date());
    }


}
