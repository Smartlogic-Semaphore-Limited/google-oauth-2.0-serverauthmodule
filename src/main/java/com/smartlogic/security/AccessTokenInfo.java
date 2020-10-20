package com.smartlogic.security;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.annotations.SerializedName;

/**
 * Information about access token;
 *
 * @author pdgreen
 * @author rahlander
 */
public class AccessTokenInfo {

  private static Logger LOGGER = Logger.getLogger(AccessTokenInfo.class.getName());

  @SerializedName("access_token")
  private final String accessToken;
  @SerializedName("id_token")
  private final String idToken;
  @SerializedName("expires_in")
  private final Date expiration;
  @SerializedName("token_type")
  private final String type;

  public AccessTokenInfo() {
    this.accessToken = null;
    this.expiration = null;
    this.type = null;
    this.idToken = null;
  }

  public String getAccessToken() {
    return accessToken;
  }

  public String getIdToken() {
    return idToken;
  }

  public Date getExpiration() {
    return expiration;
  }

  public String getType() {
    return type;
  }

  @Override
  public String toString() {
    return getAccessToken();
  }

  public String getGroups() {
    return decodeGroups();
  }

  private String decodeGroups() {
    List<String> groups = decodeFromToken(accessToken);
    if (idToken != null) {
      groups.addAll(decodeFromToken(idToken));
    }
    return groups.stream().collect(Collectors.joining(","));
  }

  private List<String> decodeFromToken(String token) {
    List<String> groups = new ArrayList<>();
    try {
      DecodedJWT jwt = JWT.decode(token);
      Claim groupClaim = jwt.getClaims().get(ApiUtils.TOKEN_API_GROUPS_PARAMETER);
      if (groupClaim != null) {
        groups.addAll(groupClaim.asList(String.class));
      }
    } catch (JWTDecodeException ex) {
      LOGGER.log(Level.WARNING, "Couldn't get groups from token", ex);

    }
    return groups;
  }
}
