package nz.org.cacophony.birdmonitor;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import com.google.firebase.crashlytics.FirebaseCrashlytics;

import org.apache.commons.lang3.RandomStringUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;

import okhttp3.FormBody;
import okhttp3.Headers;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

import static nz.org.cacophony.birdmonitor.IdlingResourceForEspressoTesting.anyWebRequestResource;
import static nz.org.cacophony.birdmonitor.IdlingResourceForEspressoTesting.createAccountIdlingResource;
import static nz.org.cacophony.birdmonitor.IdlingResourceForEspressoTesting.getGroupsIdlingResource;
import static nz.org.cacophony.birdmonitor.IdlingResourceForEspressoTesting.registerPhoneIdlingResource;
import static nz.org.cacophony.birdmonitor.IdlingResourceForEspressoTesting.signInIdlingResource;
import static nz.org.cacophony.birdmonitor.IdlingResourceForEspressoTesting.uploadFilesIdlingResource;
import static nz.org.cacophony.birdmonitor.views.CreateAccountFragment.MessageType.FAILED_TO_CREATE_USER;
import static nz.org.cacophony.birdmonitor.views.CreateAccountFragment.MessageType.SUCCESSFULLY_CREATED_USER;
import static nz.org.cacophony.birdmonitor.views.CreateAccountFragment.SERVER_SIGNUP_ACTION;
import static nz.org.cacophony.birdmonitor.views.GroupsFragment.MessageType.FAILED_TO_ADD_GROUP;
import static nz.org.cacophony.birdmonitor.views.GroupsFragment.MessageType.FAILED_TO_RETRIEVE_GROUPS;
import static nz.org.cacophony.birdmonitor.views.GroupsFragment.MessageType.SUCCESSFULLY_ADDED_GROUP;
import static nz.org.cacophony.birdmonitor.views.GroupsFragment.MessageType.SUCCESSFULLY_RETRIEVED_GROUPS;
import static nz.org.cacophony.birdmonitor.views.GroupsFragment.SERVER_GROUPS_ACTION;
import static nz.org.cacophony.birdmonitor.views.ManageRecordingsFragment.MANAGE_RECORDINGS_ACTION;
import static nz.org.cacophony.birdmonitor.views.ManageRecordingsFragment.MessageType.CONNECTED_TO_SERVER;
import static nz.org.cacophony.birdmonitor.views.RegisterFragment.MessageType.REGISTER_ERROR_ALERT;
import static nz.org.cacophony.birdmonitor.views.RegisterFragment.MessageType.REGISTER_FAIL;
import static nz.org.cacophony.birdmonitor.views.RegisterFragment.MessageType.REGISTER_SUCCESS;
import static nz.org.cacophony.birdmonitor.views.RegisterFragment.SERVER_REGISTER_ACTION;
import static nz.org.cacophony.birdmonitor.views.SignInFragment.MessageType.INVALID_CREDENTIALS;
import static nz.org.cacophony.birdmonitor.views.SignInFragment.MessageType.NETWORK_ERROR;
import static nz.org.cacophony.birdmonitor.views.SignInFragment.MessageType.SUCCESSFULLY_SIGNED_IN;
import static nz.org.cacophony.birdmonitor.views.SignInFragment.MessageType.UNABLE_TO_SIGNIN;
import static nz.org.cacophony.birdmonitor.views.SignInFragment.SERVER_USER_LOGIN_ACTION;
import org.conscrypt.Conscrypt;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


/**
 * This class deals with connecting to the server (test connection, Login, Register, upload recording).
 */

public class Server {

    private static final String TAG = Server.class.getName();

    private static final int HTTP_422_UNPROCESSABLE_ENTITY = 422;

    private static final String UPLOAD_AUDIO_API_URL = "/api/v1/recordings";
    private static final String LOGIN_URL = "/authenticate_device";
    private static final String LOGIN_USER_URL = "/authenticate_user";
    private static final String REGISTER_URL = "/api/v1/devices";
    private static final String SIGNUP_URL = "/api/v1/users";
    private static final String GROUPS_URL = "/api/v1/groups";
    public static TrustManagerFactory getTrustManagerFactory() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException {
        //Note: hardcode it, because the device might not even have the certificate to download it over https
        String isgCert =
                "-----BEGIN CERTIFICATE-----\n" +
                        "MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw\n" +
                        "TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\n" +
                        "cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4\n" +
                        "WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu\n" +
                        "ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY\n" +
                        "MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc\n" +
                        "h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+\n" +
                        "0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U\n" +
                        "A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW\n" +
                        "T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH\n" +
                        "B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC\n" +
                        "B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv\n" +
                        "KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn\n" +
                        "OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn\n" +
                        "jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw\n" +
                        "qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI\n" +
                        "rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV\n" +
                        "HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq\n" +
                        "hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL\n" +
                        "ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ\n" +
                        "3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK\n" +
                        "NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5\n" +
                        "ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur\n" +
                        "TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC\n" +
                        "jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc\n" +
                        "oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq\n" +
                        "4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA\n" +
                        "mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d\n" +
                        "emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=\n" +
                        "-----END CERTIFICATE-----\n";

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate isgCertificate = cf.generateCertificate(new ByteArrayInputStream(isgCert.getBytes(StandardCharsets.UTF_8)));

        // Create a KeyStore containing our trusted CAs
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setCertificateEntry("isrg_root", isgCertificate);

        //Default TrustManager to get device trusted CA
        TrustManagerFactory defaultTmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        defaultTmf.init((KeyStore) null);

        X509TrustManager trustManager = (X509TrustManager) defaultTmf.getTrustManagers()[0];
        int number = 0;
        for(Certificate cert : trustManager.getAcceptedIssuers()) {
            keyStore.setCertificateEntry(Integer.toString(number), cert);
            number++;
        }

        // Create a TrustManager that trusts the CAs in our KeyStore
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);
        return tmf;
    }
    public static OkHttpClient getHttpClient() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        OkHttpClient.Builder builder = new OkHttpClient.Builder();

        if (Build.VERSION.SDK_INT <= 25) {
            TrustManagerFactory tmf = getTrustManagerFactory();
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, tmf.getTrustManagers(), null);
            builder.sslSocketFactory(context.getSocketFactory(), (X509TrustManager) tmf.getTrustManagers()[0]);
        }
        return builder.build();
    }


    private static final OkHttpClient client;

    static {
        try {
            client = getHttpClient();
        } catch (CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException |
                 KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean uploading = false;

    public static boolean login(Context context) {
        final Prefs prefs = new Prefs(context);
        try {
            Util.disableFlightMode(context);

            // Now wait for network connection as setFlightMode takes a while
            if (!Util.waitForNetworkConnection(context, true)) {
                Log.e(TAG, "Failed to get internet connection");
                return false;
            }

            String devicename = prefs.getDeviceName();
            String devicePassword = prefs.getDevicePassword();
            String group = prefs.getGroupName();
            long deviceID = prefs.getDeviceId();
            if ((deviceID == 0 && (devicename == null || group == null)) || devicePassword == null) {
                // One or more credentials are null, so can not attempt to login.
                Log.e(TAG, "No credentials to login with.");
                return false;
            }


            String loginUrl = prefs.getServerUrl() + LOGIN_URL;

            FormBody.Builder builder = new FormBody.Builder();
            if (deviceID > 0) {
                builder.add("deviceID", Long.toString(deviceID));
            } else {
                builder.add("groupname", group);
                builder.add("devicename", devicename);
            }
            builder.add("password", devicePassword);
            RequestBody requestBody = builder.build();

            WebResponse postResponse = makePost(loginUrl, requestBody);
            Response response = postResponse.response;
            JSONObject responseJson = postResponse.responseJson;


            if (response.isSuccessful()) {
                Log.i(TAG, "Successful login.");
                prefs.setDeviceToken(responseJson.getString("token"));
                Log.d(TAG, "Web token has been refreshed");
                prefs.setTokenLastRefreshed(new Date().getTime());

            } else { // STATUS not OK
                Log.e(TAG, "Invalid devicename or password for login.");
                prefs.setDeviceToken(null);
            }

        } catch (Exception e) {
            Log.e(TAG, e.getLocalizedMessage(), e);
        }
        return prefs.getToken() != null;
    }

    public static boolean loginUser(Context context) {
        signInIdlingResource.increment();
        boolean success = false;
        final Prefs prefs = new Prefs(context);

        try {
            Util.disableFlightMode(context);

            // Now wait for network connection as setFlightMode takes a while
            if (!Util.waitForNetworkConnection(context, true)) {
                Log.e(TAG, "Failed to get internet connection");
                JSONObject extraInfo = new JSONObject().put("responseCode", -1);
                String messageToDisplay = "Unable to get an internet connection";
                MessageHelper.broadcastMessage(messageToDisplay, extraInfo, NETWORK_ERROR, SERVER_USER_LOGIN_ACTION, context);
                return success;
            }

            String userName = prefs.getUsername();
            String usernameOrEmailAddress = prefs.getUserNameOrEmailAddress();
            String userNamePassword = prefs.getUsernamePassword();

            if (usernameOrEmailAddress == null) {
                usernameOrEmailAddress = userName;
            }

            if (usernameOrEmailAddress == null || userNamePassword == null) {

                // One or more credentials are null, so can not attempt to login.
                Log.e(TAG, "No credentials to login with.");
                JSONObject extraInfo = new JSONObject().put("responseCode", -1);
                String messageToDisplay = "Error: Username/email address or password can not be missing";
                MessageHelper.broadcastMessage(messageToDisplay, extraInfo, INVALID_CREDENTIALS, SERVER_USER_LOGIN_ACTION, context);

                return success;
            }


            String loginUrl = prefs.getServerUrl() + LOGIN_USER_URL;

            RequestBody requestBody = new FormBody.Builder()
                    .add("nameOrEmail", usernameOrEmailAddress)
                    .add("password", userNamePassword)
                    .build();
            WebResponse postResponse = makePost(loginUrl, requestBody);
            Response response = postResponse.response;
            JSONObject responseJson = postResponse.responseJson;

            if (response.isSuccessful()) {

                String userToken = responseJson.getString("token");
                prefs.setUserToken(userToken);
                prefs.setTokenLastRefreshed(new Date().getTime());
                prefs.setUserSignedIn(true);

                boolean isItSignedIn = prefs.getUserSignedIn();
                Log.e(TAG, "isItSignedIn" + isItSignedIn);

                String messageToDisplay = "You have successfully signed in as ";
                MessageHelper.broadcastMessage(messageToDisplay, SUCCESSFULLY_SIGNED_IN, SERVER_USER_LOGIN_ACTION, context);
                success = true;
            } else if (response.code() == HTTP_422_UNPROCESSABLE_ENTITY) {
                prefs.setUserToken(null);
                String message = "Sorry could not sign in.";
                try {
                    String errorType = responseJson.getString("errorType");
                    if (errorType != null) {
                        if (errorType.equals("validation")) {
                            message = responseJson.getString("message");
                            if (message.startsWith("_error:")) {
                                message = message.substring("_error:".length() + 1);
                            }
                        }
                    }
                } catch (Exception e) {
                    Log.w(TAG, e.getLocalizedMessage(), e);
                }
                MessageHelper.broadcastMessage(message, UNABLE_TO_SIGNIN, SERVER_USER_LOGIN_ACTION, context);

            } else {
                prefs.setUserToken(null);
                JSONArray messages = responseJson.getJSONArray("messages");
                String firstMessage = messages.optString(0, "Error, unable to sign in.");
                MessageHelper.broadcastMessage(firstMessage, UNABLE_TO_SIGNIN, SERVER_USER_LOGIN_ACTION, context);
            }

        } catch (Exception e) {
            Log.e(TAG, e.getLocalizedMessage(), e);
            String messageToDisplay = "Error, unable to sign in: " + e.getLocalizedMessage();
            MessageHelper.broadcastMessage(messageToDisplay, UNABLE_TO_SIGNIN, SERVER_USER_LOGIN_ACTION, context);
        } finally {
            signInIdlingResource.decrement();
        }
        return success;
    }

    /**
     * Does a synchronous http request to register the device. Can't be run on main/UI thread.
     *
     * @param group   Name of group to register under.
     * @param context App context.
     */
    public static void registerDevice(final String group, final String deviceName, final Context context) {
        final Prefs prefs = new Prefs(context);

        // Check that the group name is valid, at least 4 characters.
        if (group == null || group.length() < 4) {
            Log.i(TAG, "Invalid group name: " + group);
            String messageToDisplay = "Group name must be at least 4 characters";
            MessageHelper.broadcastMessage(messageToDisplay, REGISTER_FAIL, SERVER_REGISTER_ACTION, context);
            registerPhoneIdlingResource.decrement();
            return;
        }

        String registerUrl = prefs.getServerUrl() + REGISTER_URL;
        try {
            final String password = RandomStringUtils.random(20, true, true);

            RequestBody requestBody = new FormBody.Builder()
                    .add("devicename", deviceName)
                    .add("password", password)
                    .add("group", group)
                    .build();
            WebResponse postResponse = makePost(registerUrl, requestBody);
            Response response = postResponse.response;
            JSONObject responseJson = postResponse.responseJson;

            if (response.code() == HTTP_422_UNPROCESSABLE_ENTITY) {
                Log.i(TAG, "Register device response from server is 422");
                String serverMessage = responseJson.getString("message");
                String messageToDisplay = "Sorry, you had the following issues: " + serverMessage.replace("; ", " and ").toLowerCase();
                MessageHelper.broadcastMessage(messageToDisplay, REGISTER_ERROR_ALERT, SERVER_REGISTER_ACTION, context);
                return;
            }

            if (response.isSuccessful()) {
                long deviceID = 0;
                //makes backwards compatible
                if (responseJson.has("id")) {
                    deviceID = responseJson.getLong("id");
                } else {
                    deviceID = Util.getDeviceID(prefs.getToken());
                }

                FirebaseCrashlytics.getInstance().setUserId(String.format("%s-%s-%d", group, deviceName, deviceID));
                prefs.setDeviceToken(responseJson.getString("token"));
                prefs.setTokenLastRefreshed(new Date().getTime());
                prefs.setDeviceName(deviceName);
                prefs.setGroupName(group);
                prefs.setDevicePassword(password);
                prefs.setDeviceId(deviceID);
                String messageToDisplay = "Success - Your phone has been registered with the server :-)";
                MessageHelper.broadcastMessage(messageToDisplay, REGISTER_SUCCESS, SERVER_REGISTER_ACTION, context);

                return;
            }
            //Unexpected response code from server
            Log.w(TAG, String.format("Unexpected register response from server is: %s, with message: %s, and JSON response: %s",
                    response.code(), response.message(), postResponse.body));

            String errorType = responseJson.getString("errorType");
            String serverMessage = responseJson.getString("message");
            String messageToDisplay = String.format("Unable to register with an unknown error. errorType is %s, and message is %s", errorType, serverMessage);
            MessageHelper.broadcastMessage(messageToDisplay, REGISTER_FAIL, SERVER_REGISTER_ACTION, context);

        } catch (Exception e) {
            Log.w(TAG, e);
            String messageToDisplay = "An unknown error occurred: " + e.toString();
            MessageHelper.broadcastMessage(messageToDisplay, REGISTER_FAIL, SERVER_REGISTER_ACTION, context);
        } finally {
            registerPhoneIdlingResource.decrement();
        }
    }

    private static WebResponse makePost(String url, RequestBody requestBody, String authToken) throws IOException, JSONException {
        Request request = new Request.Builder()
                .url(url)
                .header("Authorization", authToken)
                .post(requestBody)
                .build();
        return submitRequest(request);
    }

    private static WebResponse makePost(String url, RequestBody requestBody) throws IOException, JSONException {
        Request request = new Request.Builder()
                .url(url)
                .post(requestBody)
                .build();
        return submitRequest(request);
    }

    private static WebResponse submitRequest(Request request) throws IOException, JSONException {
        anyWebRequestResource.increment();
        Response response = client.newCall(request).execute();
        anyWebRequestResource.decrement();
        Log.i("MSG", response.message());
        return new WebResponse(response);
    }

    public static void signUp(final String username, final String emailAddress, final String password, final Context context) {
        createAccountIdlingResource.increment();

        final Prefs prefs = new Prefs(context);

        String signupUrl = prefs.getServerUrl() + SIGNUP_URL;

        try {
            RequestBody requestBody = new FormBody.Builder()
                    .add("username", username)
                    .add("password", password)
                    .add("email", emailAddress)
                    .build();
            WebResponse postResponse = makePost(signupUrl, requestBody);
            Response response = postResponse.response;
            JSONObject responseJson = postResponse.responseJson;

            if (response.code() == HTTP_422_UNPROCESSABLE_ENTITY) {
                Log.i(TAG, "Signup response from server is 422");
                String serverMessage = responseJson.getString("message");
                String messageToDisplay = "Sorry, you had the following issues: " + serverMessage.replace("; ", " and ").toLowerCase();
                MessageHelper.broadcastMessage(messageToDisplay, FAILED_TO_CREATE_USER, SERVER_SIGNUP_ACTION, context);
                return;
            }

            if (response.isSuccessful()) {
                prefs.setUserToken(responseJson.getString("token"));
                prefs.setUserTokenLastRefreshed(new Date().getTime());
                prefs.setUsername(username);
                prefs.setUsernamePassword(password);
                prefs.setEmailAddress(emailAddress);

                String messageToDisplay = "Success, you have successfully created a new user account";
                MessageHelper.broadcastMessage(messageToDisplay, SUCCESSFULLY_CREATED_USER, SERVER_SIGNUP_ACTION, context);
                return;
            }

            //Unexpected response code from server
            Log.w(TAG, String.format("Unexpected sign up response from server is: %s, with message: %s, and JSON response: %s",
                    response.code(), response.message(), postResponse.body));

            String errorType = responseJson.getString("errorType");
            String serverMessage = responseJson.getString("message");
            String messageToDisplay = String.format("Unable to signup with an unknown error. errorType is %s, and message is %s", errorType, serverMessage);
            MessageHelper.broadcastMessage(messageToDisplay, FAILED_TO_CREATE_USER, SERVER_SIGNUP_ACTION, context);

        } catch (Exception e) {
            Log.w(TAG, e);
            String messageToDisplay = "An unknown error occurred: " + e.getLocalizedMessage();
            MessageHelper.broadcastMessage(messageToDisplay, FAILED_TO_CREATE_USER, SERVER_SIGNUP_ACTION, context);
        } finally {
            createAccountIdlingResource.decrement();
        }
    }

    private static RequestBody createAudioPostBody(File audioFile, JSONObject data) {
        String fileName = audioFile.getName();
        String mediaType = URLConnection.guessContentTypeFromName(fileName);

        return new MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addPart(
                        Headers.of(
                                "Content-Disposition", "form-data; name=\"data\""
                        ),
                        RequestBody.create(MediaType.parse("Content-Type: text/plain; charset=UTF-8"), data.toString()))
                .addPart(
                        Headers.of(
                                "Content-Disposition", "form-data; name=\"file\"; filename=\"" + fileName + "\"",
                                "Content-Transfer-Encoding", "binary"),
                        RequestBody.create(MediaType.parse(mediaType), audioFile)
                ).build();
    }

    public static boolean uploadAudioRecording(File audioFile, JSONObject data, Context context) {
        int uploadStatus = uploadAudioRec(audioFile, data, context);
        if (uploadStatus == HttpURLConnection.HTTP_UNAUTHORIZED) {
            Log.e(TAG, "Upload unauthorized, requesting a new token and retrying");
            if (login(context)) {
                uploadStatus = uploadAudioRec(audioFile, data, context);
            }
        }

        return uploadStatus == 1;
    }

    private static int uploadAudioRec(File audioFile, JSONObject data, Context context) {
        // http://www.codejava.net/java-se/networking/upload-files-by-sending-multipart-request-programmatically
        int uploadStatus = 0;

        if (uploading) {
            Log.i(TAG, "Already uploading. Wait until last upload is finished.");
            return uploadStatus;
        }
        uploading = true;
        uploadFilesIdlingResource.increment();

        Prefs prefs = new Prefs(context);
        String uploadUrl = prefs.getServerUrl() + UPLOAD_AUDIO_API_URL;
        try {
            RequestBody requestBody = createAudioPostBody(audioFile, data);

            if (RecordAndUpload.isCancelUploadingRecordings()) {
                Log.w(TAG, "User cancelled uploading of recordings.");
                return uploadStatus;
            }

            WebResponse postResponse = makePost(uploadUrl, requestBody, prefs.getToken());
            Response response = postResponse.response;


            if (response.isSuccessful()) {
                JSONObject responseJson = postResponse.responseJson;

                MessageHelper.broadcastMessage("Connected to Server", CONNECTED_TO_SERVER, MANAGE_RECORDINGS_ACTION, context);
                Log.i(TAG, "SERVER REPLIED:");
                long recordingId = responseJson.getLong("recordingId");

                prefs.setLastRecordIdReturnedFromServer(recordingId);
                long check = prefs.getLastRecordIdReturnedFromServer();
                if (recordingId != check) {
                    Log.e(TAG, "Error with recording id");
                }
                uploadStatus = 1;
            } else {
                uploadStatus = response.code();
            }

        } catch (IOException | JSONException ex) {
            Log.e(TAG, ex.getLocalizedMessage(), ex);
        } finally {
            uploading = false;
            uploadFilesIdlingResource.decrement();
        }
        return uploadStatus;
    }

    public static ArrayList<String> getGroups(Context context) {
        getGroupsIdlingResource.increment();

        final Prefs prefs = new Prefs(context);

        ArrayList<String> groups = new ArrayList<>();
        try {
            String emptyWhereClause = "?where={}"; // API requires a WHERE json blob even though we want all matches
            String groupsUrl = prefs.getServerUrl() + GROUPS_URL + emptyWhereClause;

            String authorization = prefs.getUserToken();
            Request request = new Request.Builder()
                    .url(groupsUrl)
                    .header("Authorization", authorization)
                    .build();

            WebResponse getResponse = submitRequest(request);
            Response response = getResponse.response;
            JSONObject responseJson = getResponse.responseJson;
            Log.i(TAG, "Got groups with response code: " + response.code() + ", and body: " + getResponse.body);

            JSONObject extraInfo = new JSONObject().put("responseCode", response.code());

            if (response.isSuccessful() && !getResponse.body.isEmpty()) {

                // Get groups from responseBody
                JSONArray groupsJSONArray = responseJson.getJSONArray("groups");
                if (groupsJSONArray != null) {
                    for (int i = 0; i < groupsJSONArray.length(); i++) {
                        JSONObject groupJSONObject = new JSONObject(groupsJSONArray.getString(i));
                        String groupName = groupJSONObject.getString("groupname");
                        groups.add(groupName);
                    }
                }

                String messageToDisplay = "Success, groups have been updated from server";
                MessageHelper.broadcastMessage(messageToDisplay, extraInfo, SUCCESSFULLY_RETRIEVED_GROUPS, SERVER_GROUPS_ACTION, context);

            } else { // not success
                String messageToDisplay = "Error, unable to get groups from server";
                MessageHelper.broadcastMessage(messageToDisplay, extraInfo, FAILED_TO_RETRIEVE_GROUPS, SERVER_GROUPS_ACTION, context);
            }

        } catch (Exception ex) {
            Log.e(TAG, ex.getLocalizedMessage(), ex);
        } finally {
            getGroupsIdlingResource.decrement();
        }

        return groups;
    }

    public static boolean addGroupToServer(Context context, String groupName) {
        final Prefs prefs = new Prefs(context);

        String groupsUrl = prefs.getServerUrl() + GROUPS_URL;

        try {
            RequestBody requestBody = new FormBody.Builder()
                    .add("groupname", groupName)
                    .build();

            WebResponse postResponse = makePost(groupsUrl, requestBody, prefs.getUserToken());
            Response response = postResponse.response;

            Log.i("MSG", response.message());
            JSONObject jsonObjectMessageToBroadcast = new JSONObject().put("responseCode", response.code());

            if (response.isSuccessful()) {
                String messageToDisplay = "Success, the group " + groupName + " has been added to the server";
                // Now add it to local storage
                Util.addGroup(context, groupName);
                MessageHelper.broadcastMessage(messageToDisplay, jsonObjectMessageToBroadcast, SUCCESSFULLY_ADDED_GROUP, SERVER_GROUPS_ACTION, context);
                return true;
            } else {
                String messageToDisplay = "Sorry, the group " + groupName + " could not be added to the server";
                MessageHelper.broadcastMessage(messageToDisplay, jsonObjectMessageToBroadcast, FAILED_TO_ADD_GROUP, SERVER_GROUPS_ACTION, context);
                return false;
            }
        } catch (Exception ex) {
            Log.e(TAG, ex.getLocalizedMessage(), ex);
            return false;
        }
    }

    static class WebResponse {
        final Response response;
        final String body;
        final JSONObject responseJson;

        WebResponse(Response response) throws IOException, JSONException {
            this.response = response;
            ResponseBody responseBody = response.body();
            body = responseBody != null ? responseBody.string() : "";
            if (responseBody != null) {
                responseBody.close();
            }
            responseJson = new JSONObject(body);
        }
    }
}