package com.smartlogic.security;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.smartlogic.security.api.OAuthPrincipal;
import com.smartlogic.security.api.UserInfo;

/**
 * SAM ({@link ServerAuthModule}) for OAuth.
 *
 * @author pdgreen
 * @author rahlander
 */
public class OAuthServerAuthModule implements ServerAuthModule {

  /*
   * SAM Constants
   */
  private static final String LEARNING_CONTEXT_KEY = "javax.security.auth.login.LoginContext";
  private static final String IS_MANDATORY_INFO_KEY =
      "javax.security.auth.message.MessagePolicy.isMandatory";
  private static final String AUTH_TYPE_INFO_KEY = "javax.servlet.http.authType";
  private static final String AUTH_TYPE_OAUTH_KEY = "OAuth";
  /*
   * defaults
   */
  public static final String DEFAULT_OAUTH_CALLBACK_PATH = "/j_oauth_callback";
  public static final String DEFAULT_AUTHORIZE_API = "authorize";
  public static final String DEFAULT_TOKEN_API = "token";
  public static final String DEFAULT_USERINFO_API = "userinfo";

  /*
   * property names
   */
  private static final String LOGIN_REQUEST_PARAM_PROPERTY_NAME = "login_request_param";
  private static final String FORWARD_TO_IF_NOT_AUTHENTICATED_PROPERTY_NAME =
      "forward_to_if_not_authenticated";
  private static final String ENDPOINT_PROPERTY_NAME = "oauth.endpoint";
  private static final String AUTHORIZE_API = "oauth.auth_uri";
  private static final String TOKEN_API = "oauth.token_uri";
  private static final String USERINFO_API = "oauth.userinfo_uri";

  private static final String CLIENTID_PROPERTY_NAME = "oauth.clientid";
  private static final String CLIENTSECRET_PROPERTY_NAME = "oauth.clientsecret";
  private static final String CALLBACK_URI_PROPERTY_NAME = "oauth.callback_uri";
  private static final String CALLBACK_RELATIVE_URI_PROPERTY_NAME = "oauth.callback_relative_path";
  private static final String IGNORE_MISSING_LOGIN_CONTEXT = "ignore_missing_login_context";
  private static final String ADD_DOMAIN_AS_GROUP = "add_domain_as_group";
  private static final String DEFAULT_GROUPS_PROPERTY_NAME = "default_groups";
  private static final String SCOPE_VALUES = "oauth.scope";
  private static Logger LOGGER = Logger.getLogger(OAuthServerAuthModule.class.getName());
  protected static final Class[] SUPPORTED_MESSAGE_TYPES = new Class[] {
      javax.servlet.http.HttpServletRequest.class, javax.servlet.http.HttpServletResponse.class };
  private CallbackHandler handler;
  // properties
  private String loginForward;
  private String loginReqeustParam;
  private String clientid;
  private String clientSecret;
  private URI endpoint;
  private URI authApi;
  private URI tokenApi;
  private URI userInfoApi;
  private String oauthAuthenticationCallbackUri;
  private String oauthAuthenticationCallbackRelativePath;
  private boolean ignoreMissingLoginContext;
  private boolean addDomainAsGroup;
  private String defaultGroups;
  private OAuthCallbackHandler oAuthCallbackHandler;
  private LoginContextWrapper loginContextWrapper;
  private String scopes;

  private String retrieveOptionalProperty(final Map<String, String> properties, final String name,
      final String defaultValue) {
    LOGGER.log(Level.FINER, "retrieveOptionalProperty(_,{0},_)", name);
    return properties.getOrDefault(name, defaultValue);
  }

  private String retrieveRequiredProperty(final Map<String, String> properties, final String name)
      throws AuthException {
    LOGGER.log(Level.FINER, "retrieveRequiredProperty(_,{0})", name);
    if (properties.containsKey(name)) {
      return properties.get(name);
    } else {
      final String message = String.format("Required field '%s' not specified!", name);
      LOGGER.log(Level.SEVERE, message);
      throw new AuthException(message);
    }
  }

  @Override
  public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy,
      CallbackHandler handler, Map options) throws AuthException {
    LOGGER.log(Level.FINER, "initialize()");
    this.handler = handler;
    // properties
    this.clientid = retrieveRequiredProperty(options, CLIENTID_PROPERTY_NAME);
    this.clientSecret = retrieveRequiredProperty(options, CLIENTSECRET_PROPERTY_NAME);
    this.loginForward =
        retrieveOptionalProperty(options, FORWARD_TO_IF_NOT_AUTHENTICATED_PROPERTY_NAME, null);
    this.loginReqeustParam =
        retrieveOptionalProperty(options, LOGIN_REQUEST_PARAM_PROPERTY_NAME, null);
    try {
      this.endpoint = createURI(retrieveOptionalProperty(options, ENDPOINT_PROPERTY_NAME, null));
      this.tokenApi = createURI(
          retrieveOptionalProperty(options, TOKEN_API, this.endpoint + "/" + DEFAULT_TOKEN_API));
      this.authApi = createURI(retrieveOptionalProperty(options, AUTHORIZE_API,
          this.endpoint + "/" + DEFAULT_AUTHORIZE_API));
      this.userInfoApi = createURI(retrieveOptionalProperty(options, USERINFO_API,
          this.endpoint + "/" + DEFAULT_USERINFO_API));

    } catch (RuntimeException ex) {
      final String message = String.format("Invalid field '%s'", ENDPOINT_PROPERTY_NAME);
      LOGGER.log(Level.SEVERE, message, ex);
      final AuthException aex = new AuthException(message);
      aex.initCause(ex);
      throw aex;
    }
    /* If specified in config, this is the full callback URL. Must end with relativePath or relative path will be added */
    this.oauthAuthenticationCallbackUri =
        retrieveOptionalProperty(options, CALLBACK_URI_PROPERTY_NAME, null);
    /* The relative path for the callback. This is used to identify the callback in this code */
    this.oauthAuthenticationCallbackRelativePath =
        retrieveOptionalProperty(options, CALLBACK_RELATIVE_URI_PROPERTY_NAME, DEFAULT_OAUTH_CALLBACK_PATH);
    this.ignoreMissingLoginContext = Boolean.parseBoolean(
        retrieveOptionalProperty(options, IGNORE_MISSING_LOGIN_CONTEXT, Boolean.toString(false)));
    this.addDomainAsGroup = Boolean.parseBoolean(
        retrieveOptionalProperty(options, ADD_DOMAIN_AS_GROUP, Boolean.toString(false)));
    this.defaultGroups = retrieveOptionalProperty(options, DEFAULT_GROUPS_PROPERTY_NAME, "");
    this.scopes =
        retrieveOptionalProperty(options, SCOPE_VALUES, ApiUtils.USERINFO_API_PERMISSIONS);
    final String learningContextName = retrieveOptionalProperty(options, LEARNING_CONTEXT_KEY,
        OAuthServerAuthModule.class.getName());
    this.oAuthCallbackHandler = new OAuthCallbackHandler();
    this.loginContextWrapper =
        new LoginContextWrapper(createLoginContext(learningContextName, oAuthCallbackHandler));

    LOGGER.log(Level.FINE, "{0} initialized",
        new Object[] { OAuthServerAuthModule.class.getSimpleName() });
  }

  private URI createURI(String uri) {
    return Optional.ofNullable(uri).map(URI::create).orElse(null);
  }

  static AuthException wrapException(final String message, final LoginException loginException) {
    LOGGER.log(Level.FINE, "wrapException({0},{1})", new Object[] { message, loginException });
    final AuthException authException = new AuthException(message);
    authException.initCause(loginException);
    return authException;
  }

  /**
   * Creates a LoginContext. If No LoginModules configured for loginContextName, null is returned.
   *
   * @param loginContextName
   *                               name of the LoginContext to use
   * @param oAuthCallbackHandler
   *                               handler to pass to loginContext
   * @return LoginContext for loginContextName or null
   * @throws AuthException
   *                         thrown when LoginException is thrown during LoginContext creation
   */
  LoginContext createLoginContext(final String loginContextName,
      final OAuthCallbackHandler oAuthCallbackHandler) throws AuthException {
    try {
      final LoginContext createdLoginContext =
          new LoginContext(loginContextName, oAuthCallbackHandler);
      return createdLoginContext;
    } catch (LoginException ex) {
      if (ignoreMissingLoginContext && ex.getMessage().contains("No LoginModules configured")) {
        return null;
      } else {
        final String message = "Unable to create LoginContext";
        LOGGER.log(Level.SEVERE, message, ex);
        throw wrapException(message, ex);
      }
    } catch (SecurityException ex) {
      LOGGER.log(Level.SEVERE, "Something very bad happened!", ex);
      throw ex;
    }
  }

  @Override
  public Class[] getSupportedMessageTypes() {
    return SUPPORTED_MESSAGE_TYPES;
  }

  @Override
  public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject,
      Subject serviceSubject) throws AuthException {
    LOGGER.log(Level.FINER, "validateRequest({0}, {1}, {2})",
        new Object[] { messageInfo, clientSubject, serviceSubject });

    final HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
    final HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();

    if (isOauthResponse(request)) {
      return handleOauthResponse(messageInfo, request, response, clientSubject);
    } else if (isMandatory(messageInfo)) {
      return handleMandatoryRequest(messageInfo, request, response, clientSubject);
    } else {
      return AuthStatus.SUCCESS;
    }
  }

  AuthStatus handleOauthResponse(final MessageInfo messageInfo, final HttpServletRequest request,
      final HttpServletResponse response, final Subject clientSubject) throws AuthException {
    final String authorizationCode = request.getParameter(ApiUtils.TOKEN_API_CODE_PARAMETER);
    final String error = request.getParameter(ApiUtils.TOKEN_API_ERROR_PARAMETER);
    if (error != null && !error.isEmpty()) {
      LOGGER.log(Level.WARNING, "Error authorizing: {0}", new Object[] { error });
      // FIXME add an error page configuration and return SEND_FAILURE (how do you use FAILURE? it
      // returns blank page)
      return AuthStatus.FAILURE;
    } else {
      final String redirectUri = buildRedirectUri(request);
      final AccessTokenInfo accessTokenInfo = ApiUtils.lookupAccessTokenInfo(tokenApi, redirectUri,
          authorizationCode, clientid, clientSecret);
      LOGGER.log(Level.FINE, "Access Token: {0}", new Object[] { accessTokenInfo });

      final UserInfo userInfo = ApiUtils.retrieveUserInfo(userInfoApi, accessTokenInfo);
      if (userInfo == null) {
        // FIXME handle failure better
        return AuthStatus.SEND_FAILURE;
      } else {
        authenticate(messageInfo, request, response, clientSubject, userInfo,
            accessTokenInfo.getGroups());
        return AuthStatus.SEND_CONTINUE;
      }
    }
  }

  void authenticate(final MessageInfo messageInfo, final HttpServletRequest request,
      final HttpServletResponse response, final Subject subject, final UserInfo userInfo,
      final String tokenGroups) throws AuthException {
    final StateHelper stateHelper = new StateHelper(request);

    oAuthCallbackHandler.setUserInfo(userInfo);

    final Subject lcSubject = loginWithLoginContext();

    LOGGER.log(Level.FINE, "Subject from Login Context: {0}", lcSubject);

    String finalTokenGroups = tokenGroups;
    if ((finalTokenGroups == null || finalTokenGroups.length() < 1) && userInfo.getGroups() != null ) {
      for (String group : userInfo.getGroups()) {
        finalTokenGroups += group + ",";
      }
    }

    final List<String> groups = buildGroupNames(userInfo, lcSubject.getPrincipals(), finalTokenGroups);

    setCallerPrincipal(subject, userInfo, groups);
    messageInfo.getMap().put(AUTH_TYPE_INFO_KEY, AUTH_TYPE_OAUTH_KEY);
    stateHelper.saveSubject(subject);

    final URI orignalRequestUri = stateHelper.extractOriginalRequest();
    if (orignalRequestUri != null) {
      try {
        LOGGER.log(Level.FINE, "redirecting to original request path: {0}", orignalRequestUri);
        response.sendRedirect(orignalRequestUri.toString());
      } catch (IOException ex) {
        throw new IllegalStateException("Unable to redirect to " + orignalRequestUri, ex);
      }

    }
  }

  /**
   * Calls login with the loginContext and the retrieves the subject.
   *
   * @return subject of a loginContext after login
   * @throws AuthException
   *                         wrapped LoginException from loginContext.login()
   */
  Subject loginWithLoginContext() throws AuthException {

    try {
      loginContextWrapper.login();
      return loginContextWrapper.getSubject();
    } catch (LoginException ex) {
      throw wrapException("Unable to login with LoginContext", ex);
    }
  }

  AuthStatus handleMandatoryRequest(final MessageInfo messageInfo, final HttpServletRequest request,
      final HttpServletResponse response, final Subject clientSubject) throws AuthException {
    final StateHelper stateHelper = new StateHelper(request);

    final Subject savedSubject = stateHelper.retrieveSavedSubject();
    if (savedSubject != null) {
      LOGGER.log(Level.FINE, "Applying saved subject: {0}", savedSubject);
      applySubject(savedSubject, clientSubject);
      return AuthStatus.SUCCESS;
    } else {
      return handleMandatoryRequestForNewSubject(request, response, stateHelper);
    }
  }

  private AuthStatus handleMandatoryRequestForNewSubject(final HttpServletRequest request,
      final HttpServletResponse response, final StateHelper stateHelper) {
    LoginRequestHelper loginRequestHelper = new LoginRequestHelper(this.loginReqeustParam);
    if (loginRequestHelper.shouldAuthenticate(request.getQueryString())) {
      String query = loginRequestHelper.getQueryOmittingLoginParam(request.getQueryString());
      stateHelper.saveOriginalRequest(URI.create(request.getRequestURI()), query);
      final String redirectUri = buildRedirectUri(request);
      final URI oauthUri = ApiUtils.buildOauthAuthorizeUri(redirectUri, authApi, clientid, scopes);
      try {
        LOGGER.log(Level.FINE, "redirecting to {0} for OAuth", new Object[] { oauthUri });
        response.sendRedirect(oauthUri.toString());
      } catch (IOException ex) {
        throw new IllegalStateException("Unable to redirect to " + oauthUri, ex);
      }
      return AuthStatus.SEND_CONTINUE;
    } else if (loginForward != null) {
      RequestDispatcher dispatcher = request.getRequestDispatcher(this.loginForward);
      try {
        dispatcher.forward(request, response);
      } catch (Exception e) {
        throw new IllegalStateException("Unable to redirect to logon page", e);
      }
      return AuthStatus.SEND_CONTINUE;
    }
    LOGGER.log(Level.INFO, "send failuree");
    try {
      if (request.getHeader("Accept") != null &&
          request.getHeader("Accept").toLowerCase().contains("application/json")) {
        response.sendError(401);
      } else {
        response.sendRedirect(request.getContextPath() + "/ui/?from=" + request.getRequestURI());
      }
      return AuthStatus.SEND_FAILURE;
    } catch (IOException ex) {
      throw new IllegalStateException("Unable to send error code", ex);
    }
  }

  /**
   * Builds a list of group names which contain any groups from defaultGroups and any principals
   * from LoginContext
   *
   * @param userInfo
   *                      user being authenticate, the domain of the email may be used for a group
   * @param principals
   *                      principals from LoginContext
   * @param tokenGroups
   *                      groups discovered as a claim on the token.
   * @return list of groupNames for the user
   */
  List<String> buildGroupNames(final UserInfo userInfo, final Iterable<Principal> principals,
      final String tokenGroups) {
    final List<String> groups = new ArrayList<>();

    // add default groups if defined
    if (!defaultGroups.isEmpty()) {
      groups.addAll(Arrays.asList(defaultGroups.split(",")));
    }

    if (tokenGroups != null && !tokenGroups.isEmpty()) {
      groups.addAll(Arrays.asList(tokenGroups.split(",")));
    }

    // add domain of email as group
    if (addDomainAsGroup && userInfo.getEmail().contains("@")) {
      final String domain = userInfo.getEmail().split("@", 2)[1];
      groups.add(domain);
    }

    // add each principal as a group
    for (final Principal principal : principals) {
      groups.add(principal.getName());
    }

    return groups;
  }

  boolean isOauthResponse(final HttpServletRequest request) {
    return request.getRequestURI().contains(oauthAuthenticationCallbackRelativePath);// FIXME needs better
                                                                            // check
  }

  String buildRedirectUri(final HttpServletRequest request) {
    return buildRedirectUri(request, oauthAuthenticationCallbackRelativePath, oauthAuthenticationCallbackUri);
  }

  String buildRedirectUri(final HttpServletRequest request, String relativeUri, String callbackUri) {
    final String serverScheme = request.getScheme();
    final String serverHost = request.getServerName();
    final int serverPort = request.getServerPort();
    final String path = request.getContextPath() + relativeUri;
    try {
      /* If config does not specify an explicit callback URI, construct it and return it */
      if (callbackUri == null || callbackUri.length() < 1) {
        return new URI(serverScheme, null, serverHost, serverPort, path, null, null)
            .toString();
      }

      /* If configured callbackUri does not end with relativeUri path, add it and return */
      if (!callbackUri.endsWith(relativeUri))
        return callbackUri + relativeUri;

      return callbackUri;
    } catch (URISyntaxException ex) {
      throw new IllegalStateException("Unable to build redirectUri", ex);
    }
  }

  boolean setCallerPrincipal(Subject clientSubject, UserInfo userInfo, List<String> groups) {
    final CallerPrincipalCallback principalCallback =
        new CallerPrincipalCallback(clientSubject, new OAuthPrincipal(userInfo));

    final Callback[] callbacks;
    if (groups.isEmpty()) {
      callbacks = new Callback[] { principalCallback };
    } else {
      final GroupPrincipalCallback groupCallback =
          new GroupPrincipalCallback(clientSubject, groups.toArray(new String[0]));
      callbacks = new Callback[] { principalCallback, groupCallback };
    }

    try {
      handler.handle(callbacks);
    } catch (Exception e) {
      LOGGER.log(Level.SEVERE, "unable to set caller and groups", e);
      return false;
    }

    return true;
  }

  static void applySubject(final Subject source, Subject destination) {
    destination.getPrincipals().addAll(source.getPrincipals());
    destination.getPublicCredentials().addAll(source.getPublicCredentials());
    destination.getPrivateCredentials().addAll(source.getPrivateCredentials());
  }

  static boolean isMandatory(MessageInfo messageInfo) {
    return Boolean.parseBoolean((String) messageInfo.getMap().get(IS_MANDATORY_INFO_KEY));
  }

  @Override
  public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject)
      throws AuthException {
    LOGGER.log(Level.FINER, "secureResponse()");
    return AuthStatus.SEND_SUCCESS;
  }

  @Override
  public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
    subject.getPrincipals().clear();
    subject.getPublicCredentials().clear();
    subject.getPrivateCredentials().clear();

    try {
      loginContextWrapper.logout();
    } catch (LoginException ex) {
      throw wrapException("Unable to logout LoginContext", ex);
    }

  }
}
