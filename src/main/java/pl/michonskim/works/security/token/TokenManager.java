package pl.michonskim.works.security.token;

import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import pl.michonskim.works.dto.TokensDto;
import pl.michonskim.works.entity.User;
import pl.michonskim.works.exception.TokenManagerException;
import pl.michonskim.works.repository.UserRepository;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class TokenManager {

    private final UserRepository userRepository;
    private final SecretKey secretKey;

    // authentication to obiekt ktory bedziemy otrzymywac na etapie
    // logowania - jak sie zalogujemy to ten obiekt pozwoli na wyciagniecie
    // z niego danych zalogowanego usera, na podstawie ktorych wygenerujemy token
    public TokensDto generateTokens(Authentication authentication) {

        if (authentication == null) {
            throw new TokenManagerException("authentication object is null");
        }

        User user = userRepository
                .findByName(authentication.getName())
                .orElseThrow(() -> new TokenManagerException("no user with username " + authentication.getName()));

        Date creationDate = new Date();
        long accessTokenExpirationDateInMillis = System.currentTimeMillis() + TokenConfigurationData.ACCESS_TOKEN_EXPIRATION_TIME;
        Date accessTokenExpirationDate = new Date(accessTokenExpirationDateInMillis);
        Date refreshTokenExpirationDate = new Date(System.currentTimeMillis() + TokenConfigurationData.REFRESH_TOKEN_EXPIRATION_TIME);

        String accessToken = Jwts.builder()
                .setSubject(user.getId().toString())
                .setIssuedAt(creationDate)
                .setExpiration(accessTokenExpirationDate)
                .signWith(secretKey)
                .compact();

        String refreshToken = Jwts.builder()
                .setSubject(user.getId().toString())
                .setIssuedAt(creationDate)
                .setExpiration(refreshTokenExpirationDate)
                .claim(TokenConfigurationData.ACCESS_TOKEN_EXPIRATION_TIME_IN_REFRESH_TOKEN, accessTokenExpirationDateInMillis)
                .signWith(secretKey)
                .compact();

        return TokensDto
                .builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

}
