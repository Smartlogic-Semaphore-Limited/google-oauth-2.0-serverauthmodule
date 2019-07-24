package com.smartlogic.security.api;

import java.io.Serializable;
import com.google.gson.annotations.SerializedName;

/**
 * User information from OAuth account.
 *
 * @author pdgreen
 * @author rahlander
 */
public class UserInfo implements Serializable {

	private static final long serialVersionUID = 1L;

  private final String id;
  private final String sub;
  private final String email;
  @SerializedName("email_verified")
  private final boolean verifiedEmail;
  private final String name;
  @SerializedName("given_name")
  private final String givenName;
  @SerializedName("family_name")
  private final String familyName;
  private final String gender;
  private final String link;
  private final String picture;
  private final String locale;
  private final String[] groups;

  public UserInfo() {
    this.id = null;
    this.sub = null;
    this.email = null;
    this.verifiedEmail = false;
    this.name = null;
    this.givenName = null;
    this.familyName = null;
    this.gender = null;
    this.link = null;
    this.picture = null;
    this.locale = null;
    this.groups = null;
  }

  public String getEmail() {
    return email;
  }

  public String getFamilyName() {
    return familyName;
  }

  public String getGender() {
    return gender;
  }

  public String getGivenName() {
    return givenName;
  }

  public String getId() {
    if(id == null || id.isEmpty()) {
      // If the is is not set, then return the sub as the identifier
      return sub;
    }
    return id;
  }

  public String getLink() {
    return link;
  }

  public String getLocale() {
    return locale;
  }

  public String getName() {
    return name;
  }

  public String getPicture() {
    return picture;
  }

  public boolean isVerifiedEmail() {
    return verifiedEmail;
  }

  public String[] getGroups() {
    return groups;
  }
}
