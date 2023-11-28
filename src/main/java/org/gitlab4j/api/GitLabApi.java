package org.gitlab4j.api;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.WeakHashMap;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.gitlab4j.api.Constants.TokenType;
import org.gitlab4j.api.models.OauthTokenResponse;
import org.gitlab4j.api.models.User;
import org.gitlab4j.api.models.Version;
import org.gitlab4j.api.utils.MaskingLoggingFilter;
import org.gitlab4j.api.utils.Oauth2LoginStreamingOutput;
import org.gitlab4j.api.utils.SecretString;

/**
 * This class is provides a simplified interface to a GitLab API server, and divides the API up into
 * a separate API class for each concern.
 */
public class GitLabApi implements AutoCloseable {

    private final static Logger LOGGER = Logger.getLogger(GitLabApi.class.getName());

    /** GitLab4J default per page.  GitLab will ignore anything over 100. */
    public static final int DEFAULT_PER_PAGE = 96;

    /** Specifies the version of the GitLab API to communicate with. */
    public enum ApiVersion {
        V3, V4;

        public String getApiNamespace() {
            return ("/api/" + name().toLowerCase());
        }
    }

    // Used to keep track of GitLabApiExceptions on calls that return Optional<?>
    private static final Map<Integer, GitLabApiException> optionalExceptionMap =
            Collections.synchronizedMap(new WeakHashMap<Integer, GitLabApiException>());

    GitLabApiClient apiClient;
    private ApiVersion apiVersion;
    private String gitLabServerUrl;
    private Map<String, Object> clientConfigProperties;
    private int defaultPerPage = DEFAULT_PER_PAGE;

    private ApplicationsApi applicationsApi;
    private ApplicationSettingsApi applicationSettingsApi;
    private AuditEventApi auditEventApi;
    private AwardEmojiApi awardEmojiApi;
    private BoardsApi boardsApi;
    private CommitsApi commitsApi;
    private ContainerRegistryApi containerRegistryApi;
    private DiscussionsApi discussionsApi;
    private DeployKeysApi deployKeysApi;
    private DeploymentsApi deploymentsApi;
    private DeployTokensApi deployTokensApi;
    private EnvironmentsApi environmentsApi;
    private EpicsApi epicsApi;
    private EventsApi eventsApi;
    private ExternalStatusCheckApi externalStatusCheckApi;
    private GitLabCiYamlApi gitLabCiYaml;
    private GroupApi groupApi;
    private HealthCheckApi healthCheckApi;
    private ImportExportApi importExportApi;
    private IssuesApi issuesApi;
    private JobApi jobApi;
    private LabelsApi labelsApi;
    private LicenseApi licenseApi;
    private LicenseTemplatesApi licenseTemplatesApi;
    private MarkdownApi markdownApi;
    private MergeRequestApi mergeRequestApi;
    private MilestonesApi milestonesApi;
    private NamespaceApi namespaceApi;
    private NotesApi notesApi;
    private NotificationSettingsApi notificationSettingsApi;
    private PackagesApi packagesApi;
    private PipelineApi pipelineApi;
    private ProjectApi projectApi;
    private ProtectedBranchesApi protectedBranchesApi;
	private ReleaseLinksApi releaseLinksApi;
    private ReleasesApi releasesApi;
    private RepositoryApi repositoryApi;
    private RepositoryFileApi repositoryFileApi;
    private ResourceLabelEventsApi resourceLabelEventsApi;
    private ResourceStateEventsApi resourceStateEventsApi;
    private RunnersApi runnersApi;
    private SearchApi searchApi;
    private ServicesApi servicesApi;
    private SnippetsApi snippetsApi;
    private SystemHooksApi systemHooksApi;
    private TagsApi tagsApi;
    private TodosApi todosApi;
    private TopicsApi topicsApi;
    private UserApi userApi;
    private WikisApi wikisApi;
    private KeysApi keysApi;
    private MetadataApi metadataApi;

    /**
     * Get the GitLab4J shared Logger instance.
     *
     * @return the GitLab4J shared Logger instance
     */
    public static final Logger getLogger() {
        return (LOGGER);
    }

    /**
     * Constructs a GitLabApi instance set up to interact with the GitLab server
     * using GitLab API version 4.  This is the primary way to authenticate with
     * the GitLab REST API.
     *
     * @param hostUrl the URL of the GitLab server
     * @param personalAccessToken the private token to use for access to the API
     */
    public GitLabApi(String hostUrl, String personalAccessToken) {
        this(ApiVersion.V4, hostUrl, personalAccessToken, null);
    }

    /**
     * Constructs a GitLabApi instance set up to interact with the GitLab server using GitLab API version 4.
     *
     * @param hostUrl the URL of the GitLab server
     * @param personalAccessToken the private token to use for access to the API
     * @param secretToken use this token to validate received payloads
     */
    public GitLabApi(String hostUrl, String personalAccessToken, String secretToken) {
        this(ApiVersion.V4, hostUrl, TokenType.PRIVATE, personalAccessToken, secretToken);
    }

    /**
     * <p>Logs into GitLab using OAuth2 with the provided {@code username} and {@code password},
     * and creates a new {@code GitLabApi} instance using returned access token.</p>
     *
     * @param url GitLab URL
     * @param username user name for which private token should be obtained
     * @param password a CharSequence containing the password for a given {@code username}
     * @return new {@code GitLabApi} instance configured for a user-specific token
     * @throws GitLabApiException GitLabApiException if any exception occurs during execution
     */
    public static GitLabApi oauth2Login(String url, String username, CharSequence password) throws GitLabApiException {
        return (GitLabApi.oauth2Login(ApiVersion.V4, url, username, password, null, null, false));
    }

    /**
     * <p>Logs into GitLab using OAuth2 with the provided {@code username} and {@code password},
     * and creates a new {@code GitLabApi} instance using returned access token.</p>
     *
     * @param url GitLab URL
     * @param username user name for which private token should be obtained
     * @param password a char array holding the password for a given {@code username}
     * @return new {@code GitLabApi} instance configured for a user-specific token
     * @throws GitLabApiException GitLabApiException if any exception occurs during execution
     */
    public static GitLabApi oauth2Login(String url, String username, char[] password) throws GitLabApiException {

        try (SecretString secretPassword = new SecretString(password)) {
            return (GitLabApi.oauth2Login(ApiVersion.V4, url, username, secretPassword, null, null, false));
        }
    }

    /**
     * <p>Logs into GitLab using OAuth2 with the provided {@code username} and {@code password},
     * and creates a new {@code GitLabApi} instance using returned access token.</p>
     *
     * @param url GitLab URL
     * @param username user name for which private token should be obtained
     * @param password a CharSequence containing the password for a given {@code username}
     * @param ignoreCertificateErrors if true will set up the Jersey system ignore SSL certificate errors
     * @return new {@code GitLabApi} instance configured for a user-specific token
     * @throws GitLabApiException GitLabApiException if any exception occurs during execution
     */
    public static GitLabApi oauth2Login(String url, String username, CharSequence password, boolean ignoreCertificateErrors) throws GitLabApiException {
        return (GitLabApi.oauth2Login(ApiVersion.V4, url, username, password, null, null, ignoreCertificateErrors));
    }

    /**
     * <p>Logs into GitLab using OAuth2 with the provided {@code username} and {@code password},
     * and creates a new {@code GitLabApi} instance using returned access token.</p>
     *
     * @param url GitLab URL
     * @param username user name for which private token should be obtained
     * @param password a char array holding the password for a given {@code username}
     * @param ignoreCertificateErrors if true will set up the Jersey system ignore SSL certificate errors
     * @return new {@code GitLabApi} instance configured for a user-specific token
     * @throws GitLabApiException GitLabApiException if any exception occurs during execution
     */
    public static GitLabApi oauth2Login(String url, String username, char[] password, boolean ignoreCertificateErrors) throws GitLabApiException {

        try (SecretString secretPassword = new SecretString(password)) {
            return (GitLabApi.oauth2Login(ApiVersion.V4, url, username, secretPassword, null, null, ignoreCertificateErrors));
        }
    }

    /**
     * <p>Logs into GitLab using OAuth2 with the provided {@code username} and {@code password},
     * and creates a new {@code GitLabApi} instance using returned access token.</p>
     *
     * @param url GitLab URL
     * @param username user name for which private token should be obtained
     * @param password a CharSequence containing the password for a given {@code username}
     * @param secretToken use this token to validate received payloads
     * @param clientConfigProperties Map instance with additional properties for the Jersey client connection
     * @param ignoreCertificateErrors if true will set up the Jersey system ignore SSL certificate errors
     * @return new {@code GitLabApi} instance configured for a user-specific token
     * @throws GitLabApiException GitLabApiException if any exception occurs during execution
     */
    public static GitLabApi oauth2Login(String url, String username, CharSequence password, String secretToken,
            Map<String, Object> clientConfigProperties, boolean ignoreCertificateErrors) throws GitLabApiException {
        return (GitLabApi.oauth2Login(ApiVersion.V4, url, username, password, secretToken, clientConfigProperties, ignoreCertificateErrors));
    }

    /**
     * <p>Logs into GitLab using OAuth2 with the provided {@code username} and {@code password},
     * and creates a new {@code GitLabApi} instance using returned access token.</p>
     *
     * @param url GitLab URL
     * @param username user name for which private token should be obtained
     * @param password a char array holding the password for a given {@code username}
     * @param secretToken use this token to validate received payloads
     * @param clientConfigProperties Map instance with additional properties for the Jersey client connection
     * @param ignoreCertificateErrors if true will set up the Jersey system ignore SSL certificate errors
     * @return new {@code GitLabApi} instance configured for a user-specific token
     * @throws GitLabApiException GitLabApiException if any exception occurs during execution
     */
    public static GitLabApi oauth2Login(String url, String username, char[] password, String secretToken,
            Map<String, Object> clientConfigProperties, boolean ignoreCertificateErrors) throws GitLabApiException {

        try (SecretString secretPassword = new SecretString(password)) {
            return (GitLabApi.oauth2Login(ApiVersion.V4, url, username, secretPassword,
                secretToken, clientConfigProperties, ignoreCertificateErrors));
        }
    }

    /**
     * <p>Logs into GitLab using OAuth2 with the provided {@code username} and {@code password},
     * and creates a new {@code GitLabApi} instance using returned access token.</p>
     *
     * @param url GitLab URL
     * @param apiVersion the ApiVersion specifying which version of the API to use
     * @param username user name for which private token should be obtained
     * @param password a char array holding the password for a given {@code username}
     * @param secretToken use this token to validate received payloads
     * @param clientConfigProperties Map instance with additional properties for the Jersey client connection
     * @param ignoreCertificateErrors if true will set up the Jersey system ignore SSL certificate errors
     * @return new {@code GitLabApi} instance configured for a user-specific token
     * @throws GitLabApiException GitLabApiException if any exception occurs during execution
     */
    public static GitLabApi oauth2Login(ApiVersion apiVersion, String url, String username, char[] password, String secretToken,
            Map<String, Object> clientConfigProperties, boolean ignoreCertificateErrors) throws GitLabApiException {

        try (SecretString secretPassword = new SecretString(password)) {
            return (GitLabApi.oauth2Login(apiVersion, url, username, secretPassword,
                secretToken, clientConfigProperties, ignoreCertificateErrors));
        }
    }

    /**
     * <p>Logs into GitLab using OAuth2 with the provided {@code username} and {@code password},
     * and creates a new {@code GitLabApi} instance using returned access token.</p>
     *
     * @param url GitLab URL
     * @param apiVersion the ApiVersion specifying which version of the API to use
     * @param username user name for which private token should be obtained
     * @param password password for a given {@code username}
     * @param secretToken use this token to validate received payloads
     * @param clientConfigProperties Map instance with additional properties for the Jersey client connection
     * @param ignoreCertificateErrors if true will set up the Jersey system ignore SSL certificate errors
     * @return new {@code GitLabApi} instance configured for a user-specific token
     * @throws GitLabApiException GitLabApiException if any exception occurs during execution
     */
    public static GitLabApi oauth2Login(ApiVersion apiVersion, String url, String username, CharSequence password,
            String secretToken, Map<String, Object> clientConfigProperties, boolean ignoreCertificateErrors) throws GitLabApiException {

        if (username == null || username.trim().length() == 0) {
            throw new IllegalArgumentException("both username and email cannot be empty or null");
        }

        // Create a GitLabApi instance set up to be used to do an OAUTH2 login.
        GitLabApi gitLabApi = new GitLabApi(apiVersion, url, (String)null);
        gitLabApi.apiClient.setHostUrlToBaseUrl();

        if (ignoreCertificateErrors) {
            gitLabApi.setIgnoreCertificateErrors(true);
        }

        class Oauth2Api extends AbstractApi {
            Oauth2Api(GitLabApi gitlabApi) {
                super(gitlabApi);
            }
        }

        try (Oauth2LoginStreamingOutput stream = new Oauth2LoginStreamingOutput(username, password)) {

            Response response = new Oauth2Api(gitLabApi).post(Response.Status.OK, stream, MediaType.APPLICATION_JSON, "oauth", "token");
            OauthTokenResponse oauthToken = response.readEntity(OauthTokenResponse.class);
            gitLabApi = new GitLabApi(apiVersion, url, TokenType.OAUTH2_ACCESS, oauthToken.getAccessToken(), secretToken, clientConfigProperties);
            if (ignoreCertificateErrors) {
                gitLabApi.setIgnoreCertificateErrors(true);
            }

            return (gitLabApi);
        }
    }

    /**
     * Constructs a GitLabApi instance set up to interact with the GitLab server using the specified GitLab API version.
     *
     * @param apiVersion the ApiVersion specifying which version of the API to use
     * @param hostUrl the URL of the GitLab server
     * @param personalAccessToken the private token to use for access to the API
     */
    public GitLabApi(ApiVersion apiVersion, String hostUrl, String personalAccessToken) {
        this(apiVersion, hostUrl, personalAccessToken, null);
    }

    /**
     * Constructs a GitLabApi instance set up to interact with the GitLab server using the specified GitLab API version.
     *
     * @param apiVersion the ApiVersion specifying which version of the API to use
     * @param hostUrl the URL of the GitLab server
     * @param personalAccessToken the private token to use for access to the API
     * @param secretToken use this token to validate received payloads
     */
    public GitLabApi(ApiVersion apiVersion, String hostUrl, String personalAccessToken, String secretToken) {
        this(apiVersion, hostUrl, personalAccessToken, secretToken, null);
    }

    /**
     * Constructs a GitLabApi instance set up to interact with the GitLab server using the specified GitLab API version.
     *
     * @param apiVersion the ApiVersion specifying which version of the API to use
     * @param hostUrl the URL of the GitLab server
     * @param tokenType the type of auth the token is for, PRIVATE or ACCESS
     * @param authToken the token to use for access to the API
     */
    public GitLabApi(ApiVersion apiVersion, String hostUrl, TokenType tokenType, String authToken) {
        this(apiVersion, hostUrl, tokenType, authToken, null);
    }

    /**
     * Constructs a GitLabApi instance set up to interact with the GitLab server using GitLab API version 4.
     *
     * @param hostUrl the URL of the GitLab server
     * @param tokenType the type of auth the token is for, PRIVATE or ACCESS
     * @param authToken the token to use for access to the API
     */
    public GitLabApi(String hostUrl, TokenType tokenType, String authToken) {
        this(ApiVersion.V4, hostUrl, tokenType, authToken, null);
    }

    /**
     * Constructs a GitLabApi instance set up to interact with the GitLab server using the specified GitLab API version.
     *
     * @param apiVersion the ApiVersion specifying which version of the API to use
     * @param hostUrl the URL of the GitLab server
     * @param tokenType the type of auth the token is for, PRIVATE or ACCESS
     * @param authToken the token to use for access to the API
     * @param secretToken use this token to validate received payloads
     */
    public GitLabApi(ApiVersion apiVersion, String hostUrl, TokenType tokenType, String authToken, String secretToken) {
        this(apiVersion, hostUrl, tokenType, authToken, secretToken, null);
    }

    /**
     * Constructs a GitLabApi instance set up to interact with the GitLab server using GitLab API version 4.
     *
     * @param hostUrl the URL of the GitLab server
     * @param tokenType the type of auth the token is for, PRIVATE or ACCESS
     * @param authToken the token to use for access to the API
     * @param secretToken use this token to validate received payloads
     */
    public GitLabApi(String hostUrl, TokenType tokenType, String authToken, String secretToken) {
        this(ApiVersion.V4, hostUrl, tokenType, authToken, secretToken);
    }

    /**
     *  Constructs a GitLabApi instance set up to interact with the GitLab server specified by GitLab API version.
     *
     * @param apiVersion the ApiVersion specifying which version of the API to use
     * @param hostUrl the URL of the GitLab server
     * @param personalAccessToken to private token to use for access to the API
     * @param secretToken use this token to validate received payloads
     * @param clientConfigProperties Map instance with additional properties for the Jersey client connection
     */
    public GitLabApi(ApiVersion apiVersion, String hostUrl, String personalAccessToken, String secretToken, Map<String, Object> clientConfigProperties) {
        this(apiVersion, hostUrl, TokenType.PRIVATE, personalAccessToken, secretToken, clientConfigProperties);
    }

    /**
     *  Constructs a GitLabApi instance set up to interact with the GitLab server using GitLab API version 4.
     *
     * @param hostUrl the URL of the GitLab server
     * @param tokenType the type of auth the token is for, PRIVATE or ACCESS
     * @param authToken the token to use for access to the API
     * @param secretToken use this token to validate received payloads
     * @param clientConfigProperties Map instance with additional properties for the Jersey client connection
     */
    public GitLabApi(String hostUrl, TokenType tokenType, String authToken, String secretToken, Map<String, Object> clientConfigProperties) {
        this(ApiVersion.V4, hostUrl, tokenType, authToken, secretToken, clientConfigProperties);
    }

   /**
     *  Constructs a GitLabApi instance set up to interact with the GitLab server using GitLab API version 4.
     *
     * @param hostUrl the URL of the GitLab server
     * @param personalAccessToken the private token to use for access to the API
     * @param secretToken use this token to validate received payloads
     * @param clientConfigProperties Map instance with additional properties for the Jersey client connection
     */
    public GitLabApi(String hostUrl, String personalAccessToken, String secretToken, Map<String, Object> clientConfigProperties) {
        this(ApiVersion.V4, hostUrl, TokenType.PRIVATE, personalAccessToken, secretToken, clientConfigProperties);
    }

    /**
      *  Constructs a GitLabApi instance set up to interact with the GitLab server using GitLab API version 4.
      *
      * @param hostUrl the URL of the GitLab server
      * @param personalAccessToken the private token to use for access to the API
      * @param clientConfigProperties Map instance with additional properties for the Jersey client connection
      */
     public GitLabApi(String hostUrl, String personalAccessToken, Map<String, Object> clientConfigProperties) {
         this(ApiVersion.V4, hostUrl, TokenType.PRIVATE, personalAccessToken, null, clientConfigProperties);
     }

    /**
     *  Constructs a GitLabApi instance set up to interact with the GitLab server specified by GitLab API version.
     *
     * @param apiVersion the ApiVersion specifying which version of the API to use
     * @param hostUrl the URL of the GitLab server
     * @param tokenType the type of auth the token is for, PRIVATE or ACCESS
     * @param authToken to token to use for access to the API
     * @param secretToken use this token to validate received payloads
     * @param clientConfigProperties Map instance with additional properties for the Jersey client connection
     */
    public GitLabApi(ApiVersion apiVersion, String hostUrl, TokenType tokenType, String authToken, String secretToken, Map<String, Object> clientConfigProperties) {
        this.apiVersion = apiVersion;
        this.gitLabServerUrl = hostUrl;
        this.clientConfigProperties = clientConfigProperties;
        apiClient = new GitLabApiClient(apiVersion, hostUrl, tokenType, authToken, secretToken, clientConfigProperties);
    }

    /**
     * Create a new GitLabApi instance that is logically a duplicate of this instance, with the exception of sudo state.
     *
     * @return a new GitLabApi instance that is logically a duplicate of this instance, with the exception of sudo state.
     */
    public final GitLabApi duplicate() {

        Long sudoUserId = this.getSudoAsId();
        GitLabApi gitLabApi = new GitLabApi(apiVersion, gitLabServerUrl,
                getTokenType(), getAuthToken(), getSecretToken(), clientConfigProperties);
        if (sudoUserId != null) {
            gitLabApi.apiClient.setSudoAsId(sudoUserId);
        }

        if (getIgnoreCertificateErrors()) {
            gitLabApi.setIgnoreCertificateErrors(true);
        }

        gitLabApi.defaultPerPage = this.defaultPerPage;
        return (gitLabApi);
    }

    /**
     * Close the underlying {@link javax.ws.rs.client.Client} and its associated resources.
     */
    @Override
    public void close() {
        if (apiClient != null) {
            apiClient.close();
        }
    }

    /**
     * Sets the per request connect and read timeout.
     *
     * @param connectTimeout the per request connect timeout in milliseconds, can be null to use default
     * @param readTimeout the per request read timeout in milliseconds, can be null to use default
     */
    public void setRequestTimeout(Integer connectTimeout, Integer readTimeout) {
	apiClient.setRequestTimeout(connectTimeout, readTimeout);
    }

    /**
     * Fluent method that sets the per request connect and read timeout.
     *
     * @param connectTimeout the per request connect timeout in milliseconds, can be null to use default
     * @param readTimeout the per request read timeout in milliseconds, can be null to use default
     * @return this GitLabApi instance
     */
    public GitLabApi withRequestTimeout(Integer connectTimeout, Integer readTimeout) {
	apiClient.setRequestTimeout(connectTimeout, readTimeout);
	return (this);
    }

    /**
     * Enable the logging of the requests to and the responses from the GitLab server API
     * using the GitLab4J shared Logger instance and Level.FINE as the level.
     *
     * @return this GitLabApi instance
     */
    public GitLabApi withRequestResponseLogging() {
        enableRequestResponseLogging();
        return (this);
    }

    /**
     * Enable the logging of the requests to and the responses from the GitLab server API
     * using the GitLab4J shared Logger instance.
     *
     * @param level the logging level (SEVERE, WARNING, INFO, CONFIG, FINE, FINER, FINEST)
     * @return this GitLabApi instance
     */
    public GitLabApi withRequestResponseLogging(Level level) {
        enableRequestResponseLogging(level);
        return (this);
    }

    /**
     * Enable the logging of the requests to and the responses from the GitLab server API.
     *
     * @param logger the Logger instance to log to
     * @param level the logging level (SEVERE, WARNING, INFO, CONFIG, FINE, FINER, FINEST)
     * @return this GitLabApi instance
     */
    public GitLabApi withRequestResponseLogging(Logger logger, Level level) {
        enableRequestResponseLogging(logger, level);
        return (this);
    }

    /**
     * Enable the logging of the requests to and the responses from the GitLab server API
     * using the GitLab4J shared Logger instance and Level.FINE as the level.
     */
    public void enableRequestResponseLogging() {
        enableRequestResponseLogging(LOGGER, Level.FINE);
    }

    /**
     * Enable the logging of the requests to and the responses from the GitLab server API
     * using the GitLab4J shared Logger instance. Logging will NOT include entity logging and
     * will mask PRIVATE-TOKEN and Authorization headers.
     *
     * @param level the logging level (SEVERE, WARNING, INFO, CONFIG, FINE, FINER, FINEST)
     */
    public void enableRequestResponseLogging(Level level) {
        enableRequestResponseLogging(LOGGER, level, 0);
    }

    /**
     * Enable the logging of the requests to and the responses from the GitLab server API using the
     * specified logger. Logging will NOT include entity logging and will mask PRIVATE-TOKEN
     * and Authorization headers..
     *
     * @param logger the Logger instance to log to
     * @param level the logging level (SEVERE, WARNING, INFO, CONFIG, FINE, FINER, FINEST)
     */
    public void enableRequestResponseLogging(Logger logger, Level level) {
        enableRequestResponseLogging(logger, level, 0);
    }

    /**
     * Enable the logging of the requests to and the responses from the GitLab server API using the
     * GitLab4J shared Logger instance. Logging will mask PRIVATE-TOKEN and Authorization headers.
     *
     * @param level the logging level (SEVERE, WARNING, INFO, CONFIG, FINE, FINER, FINEST)
     * @param maxEntitySize maximum number of entity bytes to be logged.  When logging if the maxEntitySize
     * is reached, the entity logging  will be truncated at maxEntitySize and "...more..." will be added at
     * the end of the log entry. If maxEntitySize is &lt;= 0, entity logging will be disabled
     */
    public void enableRequestResponseLogging(Level level, int maxEntitySize) {
        enableRequestResponseLogging(LOGGER, level, maxEntitySize);
    }

    /**
     * Enable the logging of the requests to and the responses from the GitLab server API using the
     * specified logger. Logging will mask PRIVATE-TOKEN and Authorization headers.
     *
     * @param logger the Logger instance to log to
     * @param level the logging level (SEVERE, WARNING, INFO, CONFIG, FINE, FINER, FINEST)
     * @param maxEntitySize maximum number of entity bytes to be logged.  When logging if the maxEntitySize
     * is reached, the entity logging  will be truncated at maxEntitySize and "...more..." will be added at
     * the end of the log entry. If maxEntitySize is &lt;= 0, entity logging will be disabled
     */
    public void enableRequestResponseLogging(Logger logger, Level level, int maxEntitySize) {
        enableRequestResponseLogging(logger, level, maxEntitySize, MaskingLoggingFilter.DEFAULT_MASKED_HEADER_NAMES);
    }

    /**
     * Enable the logging of the requests to and the responses from the GitLab server API using the
     * GitLab4J shared Logger instance.
     *
     * @param level the logging level (SEVERE, WARNING, INFO, CONFIG, FINE, FINER, FINEST)
     * @param maskedHeaderNames a list of header names that should have the values masked
     */
    public void enableRequestResponseLogging(Level level, List<String> maskedHeaderNames) {
        apiClient.enableRequestResponseLogging(LOGGER, level, 0, maskedHeaderNames);
    }

    /**
     * Enable the logging of the requests to and the responses from the GitLab server API using the
     * specified logger.
     *
     * @param logger the Logger instance to log to
     * @param level the logging level (SEVERE, WARNING, INFO, CONFIG, FINE, FINER, FINEST)
     * @param maskedHeaderNames a list of header names that should have the values masked
     */
    public void enableRequestResponseLogging(Logger logger, Level level, List<String> maskedHeaderNames) {
        apiClient.enableRequestResponseLogging(logger, level, 0, maskedHeaderNames);
    }

    /**
     * Enable the logging of the requests to and the responses from the GitLab server API using the
     * GitLab4J shared Logger instance.
     *
     * @param level the logging level (SEVERE, WARNING, INFO, CONFIG, FINE, FINER, FINEST)
     * @param maxEntitySize maximum number of entity bytes to be logged.  When logging if the maxEntitySize
     * is reached, the entity logging  will be truncated at maxEntitySize and "...more..." will be added at
     * the end of the log entry. If maxEntitySize is &lt;= 0, entity logging will be disabled
     * @param maskedHeaderNames a list of header names that should have the values masked
     */
    public void enableRequestResponseLogging(Level level, int maxEntitySize, List<String> maskedHeaderNames) {
        apiClient.enableRequestResponseLogging(LOGGER, level, maxEntitySize, maskedHeaderNames);
    }

    /**
     * Enable the logging of the requests to and the responses from the GitLab server API using the
     * specified logger.
     *
     * @param logger the Logger instance to log to
     * @param level the logging level (SEVERE, WARNING, INFO, CONFIG, FINE, FINER, FINEST)
     * @param maxEntitySize maximum number of entity bytes to be logged.  When logging if the maxEntitySize
     * is reached, the entity logging  will be truncated at maxEntitySize and "...more..." will be added at
     * the end of the log entry. If maxEntitySize is &lt;= 0, entity logging will be disabled
     * @param maskedHeaderNames a list of header names that should have the values masked
     */
    public void enableRequestResponseLogging(Logger logger, Level level, int maxEntitySize, List<String> maskedHeaderNames) {
        apiClient.enableRequestResponseLogging(logger, level, maxEntitySize, maskedHeaderNames);
    }

    /**
     * Sets up all future calls to the GitLab API to be done as another user specified by sudoAsUsername.
     * To revert back to normal non-sudo operation you must call unsudo(), or pass null as the username.
     *
     * @param sudoAsUsername the username to sudo as, null will turn off sudo
     * @throws GitLabApiException if any exception occurs
     */
    public void sudo(String sudoAsUsername) throws GitLabApiException {

        if (sudoAsUsername == null || sudoAsUsername.trim().length() == 0) {
            apiClient.setSudoAsId(null);
            return;
        }

        // Get the User specified by username, if you are not an admin or the username is not found, this will fail
        User user = getUserApi().getUser(sudoAsUsername);
        if (user == null || user.getId() == null) {
            throw new GitLabApiException("the specified username was not found");
        }

        Long sudoAsId = user.getId();
        apiClient.setSudoAsId(sudoAsId);
    }

    /**
     * Turns off the currently configured sudo as ID.
     */
    public void unsudo() {
        apiClient.setSudoAsId(null);
    }

    /**
     * Sets up all future calls to the GitLab API to be done as another user specified by provided user ID.
     * To revert back to normal non-sudo operation you must call unsudo(), or pass null as the sudoAsId.
     *
     * @param sudoAsId the ID of the user to sudo as, null will turn off sudo
     * @throws GitLabApiException if any exception occurs
     */
    public void setSudoAsId(Long sudoAsId) throws GitLabApiException {

        if (sudoAsId == null) {
            apiClient.setSudoAsId(null);
            return;
        }

        // Get the User specified by the sudoAsId, if you are not an admin or the username is not found, this will fail
        User user = getUserApi().getUser(sudoAsId);
        if (user == null || !user.getId().equals(sudoAsId)) {
            throw new GitLabApiException("the specified user ID was not found");
        }

        apiClient.setSudoAsId(sudoAsId);
    }

    /**
     * Get the current sudo as ID, will return null if not in sudo mode.
     *
     * @return the current sudo as ID, will return null if not in sudo mode
     */
    public Long getSudoAsId() {
        return (apiClient.getSudoAsId());
    }

    /**
     * Get the auth token being used by this client.
     *
     * @return the auth token being used by this client
     */
    public String getAuthToken() {
        return (apiClient.getAuthToken());
    }

    /**
     * Set auth token supplier for gitlab api client.
     * @param authTokenSupplier - supplier which provide actual auth token
     */
    public void setAuthTokenSupplier(Supplier<String> authTokenSupplier) {
        apiClient.setAuthTokenSupplier(authTokenSupplier);
    }

    /**
     * Get the secret token.
     *
     * @return the secret token
     */
    public String getSecretToken() {
        return (apiClient.getSecretToken());
    }

    /**
     * Get the TokenType this client is using.
     *
     * @return the TokenType this client is using
     */
    public TokenType getTokenType() {
        return (apiClient.getTokenType());
    }

    /**
     * Return the GitLab API version that this instance is using.
     *
     * @return the GitLab API version that this instance is using
     */
    public ApiVersion getApiVersion() {
        return (apiVersion);
    }

    /**
     * Get the URL to the GitLab server.
     *
     * @return the URL to the GitLab server
     */
    public String getGitLabServerUrl() {
        return (gitLabServerUrl);
    }

    /**
     * Get the default number per page for calls that return multiple items.
     *
     * @return the default number per page for calls that return multiple item
     */
    public int getDefaultPerPage() {
        return (defaultPerPage);
    }

    /**
     * Set the default number per page for calls that return multiple items.
     *
     * @param defaultPerPage the new default number per page for calls that return multiple item
     */
    public void setDefaultPerPage(int defaultPerPage) {
        this.defaultPerPage = defaultPerPage;
    }

    /**
     * Return the GitLabApiClient associated with this instance. This is used by all the sub API classes
     * to communicate with the GitLab API.
     *
     * @return the GitLabApiClient associated with this instance
     */
    GitLabApiClient getApiClient() {
        return (apiClient);
    }

    /**
     * Returns true if the API is setup to ignore SSL certificate errors, otherwise returns false.
     *
     * @return true if the API is setup to ignore SSL certificate errors, otherwise returns false
     */
    public boolean getIgnoreCertificateErrors() {
        return (apiClient.getIgnoreCertificateErrors());
    }

    /**
     * Sets up the Jersey system ignore SSL certificate errors or not.
     *
     * @param ignoreCertificateErrors if true will set up the Jersey system ignore SSL certificate errors
     */
    public void setIgnoreCertificateErrors(boolean ignoreCertificateErrors) {
        apiClient.setIgnoreCertificateErrors(ignoreCertificateErrors);
    }

    /**
     * Get the version info for the GitLab server using the GitLab Version API.
     *
     * @return the version info for the GitLab server
     * @throws GitLabApiException if any exception occurs
     */
    public Version getVersion() throws GitLabApiException {

        class VersionApi extends AbstractApi {
            VersionApi(GitLabApi gitlabApi) {
                super(gitlabApi);
            }
        }

        Response response = new VersionApi(this).get(Response.Status.OK, null, "version");
        return (response.readEntity(Version.class));
    }

    /**
     * Gets the ApplicationsApi instance owned by this GitLabApi instance. The ApplicationsApi is used
     * to perform all OAUTH application related API calls.
     *
     * @return the ApplicationsApi instance owned by this GitLabApi instance
     */
    public ApplicationsApi getApplicationsApi() {
        ApplicationsApi localRef = applicationsApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = applicationsApi;
                if (localRef == null) {
                    localRef = new ApplicationsApi(this);
                    applicationsApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the ApplicationSettingsApi instance owned by this GitLabApi instance. The ApplicationSettingsApi is used
     * to perform all application settingsrelated API calls.
     *
     * @return the ApplicationsApi instance owned by this GitLabApi instance
     */
    public ApplicationSettingsApi getApplicationSettingsApi() {
        ApplicationSettingsApi localRef = applicationSettingsApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = applicationSettingsApi;
                if (localRef == null) {
                    localRef = new ApplicationSettingsApi(this);
                    applicationSettingsApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the AuditEventApi instance owned by this GitLabApi instance. The AuditEventApi is used
     * to perform all instance audit event API calls.
     *
     * @return the AuditEventApi instance owned by this GitLabApi instance
     */
    public AuditEventApi getAuditEventApi() {
        AuditEventApi localRef = auditEventApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = auditEventApi;
                if (localRef == null) {
                    localRef = new AuditEventApi(this);
                    auditEventApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the AwardEmojiApi instance owned by this GitLabApi instance. The AwardEmojiApi is used
     * to perform all award emoji related API calls.
     *
     * @return the AwardEmojiApi instance owned by this GitLabApi instance
     */
    public AwardEmojiApi getAwardEmojiApi() {
        AwardEmojiApi localRef = awardEmojiApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = awardEmojiApi;
                if (localRef == null) {
                    localRef = new AwardEmojiApi(this);
                    awardEmojiApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the BoardsApi instance owned by this GitLabApi instance. The BoardsApi is used
     * to perform all Issue Boards related API calls.
     *
     * @return the BoardsApi instance owned by this GitLabApi instance
     */
    public BoardsApi getBoardsApi() {
        BoardsApi localRef = boardsApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = boardsApi;
                if (localRef == null) {
                    localRef = new BoardsApi(this);
                    boardsApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the CommitsApi instance owned by this GitLabApi instance. The CommitsApi is used
     * to perform all commit related API calls.
     *
     * @return the CommitsApi instance owned by this GitLabApi instance
     */
    public CommitsApi getCommitsApi() {
        CommitsApi localRef = commitsApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = commitsApi;
                if (localRef == null) {
                    localRef = new CommitsApi(this);
                    commitsApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the ContainerRegistryApi instance owned by this GitLabApi instance. The ContainerRegistryApi is used
     * to perform all Docker Registry related API calls.
     *
     * @return the ContainerRegistryApi instance owned by this GitLabApi instance
     */
    public ContainerRegistryApi getContainerRegistryApi() {
        ContainerRegistryApi localInstance = containerRegistryApi;

        if (localInstance == null) {
            synchronized (this) {
                localInstance = containerRegistryApi;
                if (localInstance == null) {
                    containerRegistryApi = localInstance = new ContainerRegistryApi(this);
                }
            }
        }

        return localInstance;
    }

    /**
     * Gets the DeployKeysApi instance owned by this GitLabApi instance. The DeployKeysApi is used
     * to perform all deploy key related API calls.
     *
     * @return the DeployKeysApi instance owned by this GitLabApi instance
     */
    public DeployKeysApi getDeployKeysApi() {
        DeployKeysApi localRef = deployKeysApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = deployKeysApi;
                if (localRef == null) {
                    localRef = new DeployKeysApi(this);
                    deployKeysApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the DeployKeysApi instance owned by this GitLabApi instance. The DeploymentsApi is used
     * to perform all deployment related API calls.
     *
     * @return the DeploymentsApi instance owned by this GitLabApi instance
     */
    public DeploymentsApi getDeploymentsApi() {
        DeploymentsApi localRef = deploymentsApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = deploymentsApi;
                if (localRef == null) {
                    localRef = new DeploymentsApi(this);
                    deploymentsApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the DeployTokensApi instance owned by this GitLabApi instance. The DeployTokensApi is used
     * to perform all deploy token related API calls.
     *
     * @return the DeployTokensApi instance owned by this GitLabApi instance
     */
    public DeployTokensApi getDeployTokensApi() {
        DeployTokensApi localRef = deployTokensApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = deployTokensApi;
                if (localRef == null) {
                    localRef = new DeployTokensApi(this);
                    deployTokensApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the DiscussionsApi instance owned by this GitLabApi instance. The DiscussionsApi is used
     * to perform all discussion related API calls.
     *
     * @return the DiscussionsApi instance owned by this GitLabApi instance
     */
    public DiscussionsApi getDiscussionsApi() {
        DiscussionsApi localRef = discussionsApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = discussionsApi;
                if (localRef == null) {
                    localRef = new DiscussionsApi(this);
                    discussionsApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the EnvironmentsApi instance owned by this GitLabApi instance. The EnvironmentsApi is used
     * to perform all environment related API calls.
     *
     * @return the EnvironmentsApi instance owned by this GitLabApi instance
     */
    public EnvironmentsApi getEnvironmentsApi() {
        EnvironmentsApi localRef = environmentsApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = environmentsApi;
                if (localRef == null) {
                    localRef = new EnvironmentsApi(this);
                    environmentsApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the EpicsApi instance owned by this GitLabApi instance. The EpicsApi is used
     * to perform all Epics and Epic Issues related API calls.
     *
     * @return the EpicsApi instance owned by this GitLabApi instance
     */
    public EpicsApi getEpicsApi() {
        EpicsApi localRef = epicsApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = epicsApi;
                if (localRef == null) {
                    localRef = new EpicsApi(this);
                    epicsApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the EventsApi instance owned by this GitLabApi instance. The EventsApi is used
     * to perform all events related API calls.
     *
     * @return the EventsApi instance owned by this GitLabApi instance
     */
    public EventsApi getEventsApi() {
        EventsApi localRef = eventsApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = eventsApi;
                if (localRef == null) {
                    localRef = new EventsApi(this);
                    eventsApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the ExternalStatusCheckApi instance owned by this GitLabApi instance. The ExternalStatusCheckApi is used
     * to perform all the external status checks related API calls.
     *
     * @return the ExternalStatusCheckApi instance owned by this GitLabApi instance
     */
    public ExternalStatusCheckApi getExternalStatusCheckApi() {
        ExternalStatusCheckApi localRef = externalStatusCheckApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = externalStatusCheckApi;
                if (localRef == null) {
                    localRef = new ExternalStatusCheckApi(this);
                    externalStatusCheckApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the GitLabCiYamlApi instance owned by this GitLabApi instance. The GitLabCiYamlApi is used to get Gitlab CI YAML templates.
     *
     * @return the GitLabCiYamlApi instance owned by this GitLabApi instance
     */
    public GitLabCiYamlApi getGitLabCiYamlApi() {
        GitLabCiYamlApi localRef = gitLabCiYaml;

        if (localRef == null) {
            synchronized (this) {
                localRef = gitLabCiYaml;
                if (localRef == null) {
                    localRef = new GitLabCiYamlApi(this);
                    gitLabCiYaml = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the GroupApi instance owned by this GitLabApi instance. The GroupApi is used
     * to perform all group related API calls.
     *
     * @return the GroupApi instance owned by this GitLabApi instance
     */
    public GroupApi getGroupApi() {
        GroupApi localRef = groupApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = groupApi;
                if (localRef == null) {
                    localRef = new GroupApi(this);
                    groupApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the HealthCheckApi instance owned by this GitLabApi instance. The HealthCheckApi is used
     * to perform all admin level gitlab health monitoring.
     *
     * @return the HealthCheckApi instance owned by this GitLabApi instance
     */
    public HealthCheckApi getHealthCheckApi() {
        HealthCheckApi localRef = healthCheckApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = healthCheckApi;
                if (localRef == null) {
                    localRef = new HealthCheckApi(this);
                    healthCheckApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the ImportExportApi instance owned by this GitLabApi instance. The ImportExportApi is used
     * to perform all project import/export related API calls.
     *
     * @return the ImportExportApi instance owned by this GitLabApi instance
     */
    public ImportExportApi getImportExportApi() {
        ImportExportApi localRef = importExportApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = importExportApi;
                if (localRef == null) {
                    localRef = new ImportExportApi(this);
                    importExportApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the IssuesApi instance owned by this GitLabApi instance. The IssuesApi is used
     * to perform all issue related API calls.
     *
     * @return the IssuesApi instance owned by this GitLabApi instance
     */
    public IssuesApi getIssuesApi() {
        IssuesApi localRef = issuesApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = issuesApi;
                if (localRef == null) {
                    localRef = new IssuesApi(this);
                    issuesApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the JobApi instance owned by this GitLabApi instance. The JobApi is used
     * to perform all jobs related API calls.
     *
     * @return the JobsApi instance owned by this GitLabApi instance
     */
    public JobApi getJobApi() {
        JobApi localRef = jobApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = jobApi;
                if (localRef == null) {
                    localRef = new JobApi(this);
                    jobApi = localRef;
                }
            }
        }

        return localRef;
    }

    public LabelsApi getLabelsApi() {
        LabelsApi result = labelsApi;

        if (result == null) {
            synchronized (this) {
                result = labelsApi;
                if (result == null) {
                    result = new LabelsApi(this);
                    labelsApi = result;
                }
            }
        }

        return result;
    }

    /**
     * Gets the LicenseApi instance owned by this GitLabApi instance. The LicenseApi is used
     * to perform all license related API calls.
     *
     * @return the LicenseApi instance owned by this GitLabApi instance
     */
    public LicenseApi getLicenseApi() {
        LicenseApi localRef = licenseApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = licenseApi;
                if (localRef == null) {
                    localRef = new LicenseApi(this);
                    licenseApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the LicenseTemplatesApi instance owned by this GitLabApi instance. The LicenseTemplatesApi is used
     * to perform all license template related API calls.
     *
     * @return the LicenseTemplatesApi instance owned by this GitLabApi instance
     */
    public LicenseTemplatesApi getLicenseTemplatesApi() {
        LicenseTemplatesApi localRef = licenseTemplatesApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = licenseTemplatesApi;
                if (localRef == null) {
                    localRef = new LicenseTemplatesApi(this);
                    licenseTemplatesApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the MarkdownApi instance owned by this GitLabApi instance. The MarkdownApi is used
     * to perform all markdown related API calls.
     *
     * @return the MarkdownApi instance owned by this GitLabApi instance
     */
    public MarkdownApi getMarkdownApi() {
        MarkdownApi localRef = markdownApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = markdownApi;
                if (localRef == null) {
                    localRef = new MarkdownApi(this);
                    markdownApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the MergeRequestApi instance owned by this GitLabApi instance. The MergeRequestApi is used
     * to perform all merge request related API calls.
     *
     * @return the MergeRequestApi instance owned by this GitLabApi instance
     */
    public MergeRequestApi getMergeRequestApi() {
        MergeRequestApi localRef = mergeRequestApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = mergeRequestApi;
                if (localRef == null) {
                    localRef = new MergeRequestApi(this);
                    mergeRequestApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the MilestonesApi instance owned by this GitLabApi instance.
     *
     * @return the MilestonesApi instance owned by this GitLabApi instance
     */
    public MilestonesApi getMilestonesApi() {
        MilestonesApi localRef = milestonesApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = milestonesApi;
                if (localRef == null) {
                    localRef = new MilestonesApi(this);
                    milestonesApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the NamespaceApi instance owned by this GitLabApi instance. The NamespaceApi is used
     * to perform all namespace related API calls.
     *
     * @return the NamespaceApi instance owned by this GitLabApi instance
     */
    public NamespaceApi getNamespaceApi() {
        NamespaceApi result = namespaceApi;

        if (result == null) {
            synchronized (this) {
                result = namespaceApi;
                if (result == null) {
                    namespaceApi = result = new NamespaceApi(this);
                }
            }
        }

        return result;
    }

    /**
     * Gets the NotesApi instance owned by this GitLabApi instance. The NotesApi is used
     * to perform all notes related API calls.
     *
     * @return the NotesApi instance owned by this GitLabApi instance
     */
    public NotesApi getNotesApi() {
        NotesApi localRef = notesApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = notesApi;
                if (localRef == null) {
                    localRef = new NotesApi(this);
                    notesApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the NotificationSettingsApi instance owned by this GitLabApi instance. The NotificationSettingsApi is used
     * to perform all notification settings related API calls.
     *
     * @return the NotificationSettingsApi instance owned by this GitLabApi instance
     */
    public NotificationSettingsApi getNotificationSettingsApi() {
        NotificationSettingsApi localRef = notificationSettingsApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = notificationSettingsApi;
                if (localRef == null) {
                    localRef = new NotificationSettingsApi(this);
                    notificationSettingsApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the PackagesApi instance owned by this GitLabApi instance. The PackagesApi is used
     * to perform all Package related API calls.
     *
     * @return the PackagesApi instance owned by this GitLabApi instance
     */
    public PackagesApi getPackagesApi() {
        PackagesApi localRef = packagesApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = packagesApi;
                if (localRef == null) {
                    localRef = new PackagesApi(this);
                    packagesApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the PipelineApi instance owned by this GitLabApi instance. The PipelineApi is used
     * to perform all pipeline related API calls.
     *
     * @return the PipelineApi instance owned by this GitLabApi instance
     */
    public PipelineApi getPipelineApi() {
        PipelineApi localRef = pipelineApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = pipelineApi;
                if (localRef == null) {
                    localRef = new PipelineApi(this);
                    pipelineApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the ProjectApi instance owned by this GitLabApi instance. The ProjectApi is used
     * to perform all project related API calls.
     *
     * @return the ProjectApi instance owned by this GitLabApi instance
     */
    public ProjectApi getProjectApi() {
        ProjectApi localRef = projectApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = projectApi;
                if (localRef == null) {
                    localRef = new ProjectApi(this);
                    projectApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the ProtectedBranchesApi instance owned by this GitLabApi instance. The ProtectedBranchesApi is used
     * to perform all protection related actions on a branch of a project.
     *
     * @return the ProtectedBranchesApi instance owned by this GitLabApi instance
     */
    public ProtectedBranchesApi getProtectedBranchesApi() {
        ProtectedBranchesApi localRef = protectedBranchesApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = protectedBranchesApi;
                if (localRef == null) {
                    localRef = new ProtectedBranchesApi(this);
                    protectedBranchesApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the ReleaseLinksApi instance owned by this GitLabApi instance. The ReleaseLinksApi is used
     * to perform all Release Links related API calls.
     *
     * @return the ReleaseLinksApi instance owned by this GitLabApi instance
     */
    public ReleaseLinksApi getReleaseLinksApi() {
        ReleaseLinksApi localRef = releaseLinksApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = releaseLinksApi;
                if (localRef == null) {
                    localRef = new ReleaseLinksApi(this);
                    releaseLinksApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the ReleasesApi instance owned by this GitLabApi instance. The ReleasesApi is used
     * to perform all release related API calls.
     *
     * @return the ReleasesApi instance owned by this GitLabApi instance
     */
    public ReleasesApi getReleasesApi() {
        ReleasesApi localRef = releasesApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = releasesApi;
                if (localRef == null) {
                    localRef = new ReleasesApi(this);
                    releasesApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the RepositoryApi instance owned by this GitLabApi instance. The RepositoryApi is used
     * to perform all repository related API calls.
     *
     * @return the RepositoryApi instance owned by this GitLabApi instance
     */
    public RepositoryApi getRepositoryApi() {
        RepositoryApi localRef = repositoryApi;
        if (localRef == null) {
            synchronized (this) {
                localRef = repositoryApi;
                if (localRef == null) {
                    localRef = new RepositoryApi(this);
                    repositoryApi = localRef;
                }
            }
        }
        return localRef;
    }

    /**
     * Gets the RepositoryFileApi instance owned by this GitLabApi instance. The RepositoryFileApi is used
     * to perform all repository files related API calls.
     *
     * @return the RepositoryFileApi instance owned by this GitLabApi instance
     */
    public RepositoryFileApi getRepositoryFileApi() {
        RepositoryFileApi localRef = repositoryFileApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = repositoryFileApi;
                if (localRef == null) {
                    localRef = new RepositoryFileApi(this);
                    repositoryFileApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the ResourceLabelEventsApi instance owned by this GitLabApi instance. The ResourceLabelEventsApi
     * is used to perform all Resource Label Events related API calls.
     *
     * @return the ResourceLabelEventsApi instance owned by this GitLabApi instance
     */
    public ResourceLabelEventsApi getResourceLabelEventsApi() {
        ResourceLabelEventsApi localRef = resourceLabelEventsApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = resourceLabelEventsApi;
                if (localRef == null) {
                    localRef = new ResourceLabelEventsApi(this);
                    resourceLabelEventsApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the ResourceStateEventsApi instance owned by this GitLabApi instance. The ResourceStateEventsApi
     * is used to perform all Resource State Events related API calls.
     *
     * @return the ResourceStateEventsApi instance owned by this GitLabApi instance
     */
    public ResourceStateEventsApi getResourceStateEventsApi() {
        ResourceStateEventsApi localRef = resourceStateEventsApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = resourceStateEventsApi;
                if (localRef == null) {
                    localRef = new ResourceStateEventsApi(this);
                    resourceStateEventsApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the RunnersApi instance owned by this GitLabApi instance. The RunnersApi is used
     * to perform all Runner related API calls.
     *
     * @return the RunnerApi instance owned by this GitLabApi instance
     */
    public RunnersApi getRunnersApi() {
        RunnersApi localRef = runnersApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = runnersApi;
                if (localRef == null) {
                    localRef = new RunnersApi(this);
                    runnersApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the SearchApi instance owned by this GitLabApi instance. The SearchApi is used
     * to perform search related API calls.
     *
     * @return the SearchApi instance owned by this GitLabApi instance
     */
    public SearchApi getSearchApi() {
        SearchApi localRef = searchApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = searchApi;
                if (localRef == null) {
                    localRef = new SearchApi(this);
                    searchApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the ServicesApi instance owned by this GitLabApi instance. The ServicesApi is used
     * to perform all services related API calls.
     *
     * @return the ServicesApi instance owned by this GitLabApi instance
     */
    public ServicesApi getServicesApi() {
        ServicesApi result = servicesApi;

        if (result == null) {
            synchronized (this) {
                result = servicesApi;
                if (result == null) {
                    result = new ServicesApi(this);
                    servicesApi = result;
                }
            }
        }

        return result;
    }

    /**
     * Gets the SystemHooksApi instance owned by this GitLabApi instance. All methods
     * require administrator authorization.
     *
     * @return the SystemHooksApi instance owned by this GitLabApi instance
     */
    public SystemHooksApi getSystemHooksApi() {
        SystemHooksApi localRef = systemHooksApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = systemHooksApi;
                if (localRef == null) {
                    localRef = new SystemHooksApi(this);
                    systemHooksApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the TagsApi instance owned by this GitLabApi instance. The TagsApi is used
     * to perform all tag and release related API calls.
     *
     * @return the TagsApi instance owned by this GitLabApi instance
     */
    public TagsApi getTagsApi() {
        TagsApi localRef = tagsApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = tagsApi;
                if (localRef == null) {
                    localRef = new TagsApi(this);
                    tagsApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the TopicsApi instance owned by this GitLabApi instance. The TopicsApi is used
     * to perform all tag and release related API calls.
     *
     * @return the TopicsApi instance owned by this GitLabApi instance
     */
    public TopicsApi getTopicsApi() {
        TopicsApi localRef = topicsApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = topicsApi;
                if (localRef == null) {
                    localRef = new TopicsApi(this);
                    topicsApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the SnippetsApi instance owned by this GitLabApi instance. The SnippetsApi is used
     * to perform all snippet related API calls.
     *
     * @return the SnippetsApi instance owned by this GitLabApi instance
     */
    public SnippetsApi getSnippetApi() {
        SnippetsApi localRef = snippetsApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = snippetsApi;
                if (localRef == null) {
                    localRef = new SnippetsApi(this);
                    snippetsApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the TodosApi instance owned by this GitLabApi instance. The TodosApi is used to perform all Todo related API calls.
     *
     * @return the TodosApi instance owned by this GitLabApi instance
     */
    public TodosApi getTodosApi() {
        TodosApi result = todosApi;

        if (result == null) {
            synchronized (this) {
                result = todosApi;
                if (result == null) {
                    result = new TodosApi(this);
                    todosApi = result;
                }
            }
        }

        return result;
    }

    /**
     * Gets the UserApi instance owned by this GitLabApi instance. The UserApi is used
     * to perform all user related API calls.
     *
     * @return the UserApi instance owned by this GitLabApi instance
     */
    public UserApi getUserApi() {
        UserApi localRef = userApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = userApi;
                if (localRef == null) {
                    localRef = new UserApi(this);
                    userApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the WikisApi instance owned by this GitLabApi instance. The WikisApi is used to perform all wiki related API calls.
     *
     * @return the WikisApi instance owned by this GitLabApi instance
     */
    public WikisApi getWikisApi() {
        WikisApi localRef = wikisApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = wikisApi;
                if (localRef == null) {
                    localRef = new WikisApi(this);
                    wikisApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the KeysApi instance owned by this GitLabApi instance. The KeysApi is used to look up users by their ssh key signatures
     *
     * @return the KeysApi instance owned by this GitLabApi instance
     */
    public KeysApi getKeysAPI() {
        KeysApi localRef = keysApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = keysApi;
                if (localRef == null) {
                    localRef = new KeysApi(this);
                    keysApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Gets the MetadataApi instance owned by this GitlabApi instance. The MetadataApi is used to
     * retrieve metadata information for this GitLab instance
     *
     * @return the MetadataApi instance owned by this GitlabApi instance
     */
    public MetadataApi getMetadataApi() {
        MetadataApi localRef = metadataApi;

        if (localRef == null) {
            synchronized (this) {
                localRef = metadataApi;
                if (localRef == null) {
                    localRef = new MetadataApi(this);
                    metadataApi = localRef;
                }
            }
        }

        return localRef;
    }

    /**
     * Create and return an Optional instance associated with a GitLabApiException.
     *
     * @param <T> the type of the Optional instance
     * @param glae the GitLabApiException that was the result of a call to the GitLab API
     * @return the created Optional instance
     */
    protected static final <T> Optional<T> createOptionalFromException(GitLabApiException glae) {
        Optional<T> optional = Optional.empty();
        optionalExceptionMap.put(System.identityHashCode(optional),  glae);
        return (optional);
    }

    /**
     * Get the exception associated with the provided Optional instance, or null if no exception is
     * associated with the Optional instance.
     *
     * @param optional the Optional instance to get the exception for
     * @return the exception associated with the provided Optional instance, or null if no exception is
     * associated with the Optional instance
     */
    public static final GitLabApiException getOptionalException(Optional<?> optional) {
        return (optionalExceptionMap.get(System.identityHashCode(optional)));
    }

    /**
     * Return the Optional instances contained value, if present, otherwise throw the exception that is
     * associated with the Optional instance.
     *
     * @param <T> the type for the Optional parameter
     * @param optional the Optional instance to get the value for
     * @return the value of the Optional instance if no exception is associated with it
     * @throws GitLabApiException if there was an exception associated with the Optional instance
     */
    public static final <T> T orElseThrow(Optional<T> optional) throws GitLabApiException {

        GitLabApiException glea = getOptionalException(optional);
        if (glea != null) {
            throw (glea);
        }

        return (optional.get());
    }
}
