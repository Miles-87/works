package pl.michonskim.works.security.token;

public interface TokenConfigurationData {

    String TOKEN_PREFIX = "Bearer ";
    String TOKEN_HEADER = "Authorization";
    String ACCESS_TOKEN_EXPIRATION_TIME_IN_REFRESH_TOKEN = "accessTokenExpirationTime";

    long ACCESS_TOKEN_EXPIRATION_TIME = 300_000;
    long REFRESH_TOKEN_EXPIRATION_TIME = 3000_000;
}
