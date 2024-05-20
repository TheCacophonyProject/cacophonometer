package nz.org.cacophony.birdmonitor;

import static android.Manifest.permission.ACCESS_FINE_LOCATION;
import static android.Manifest.permission.READ_PHONE_STATE;
import static android.Manifest.permission.RECORD_AUDIO;
import static android.Manifest.permission.WRITE_EXTERNAL_STORAGE;
import static android.content.Context.ALARM_SERVICE;
import static nz.org.cacophony.birdmonitor.views.GPSFragment.GPS_ACTION;
import static nz.org.cacophony.birdmonitor.views.GPSFragment.GpsMessageType.GPS_UPDATE_FAILED;
import static nz.org.cacophony.birdmonitor.views.GPSFragment.ROOT_ACTION;
import static nz.org.cacophony.birdmonitor.views.GPSFragment.RootMessageType.ERROR_DO_NOT_HAVE_ROOT;
import static nz.org.cacophony.birdmonitor.views.ManageRecordingsFragment.MANAGE_RECORDINGS_ACTION;
import static nz.org.cacophony.birdmonitor.views.ManageRecordingsFragment.MessageType.FAILED_RECORDINGS_NOT_DELETED;
import static nz.org.cacophony.birdmonitor.views.ManageRecordingsFragment.MessageType.FAILED_RECORDINGS_NOT_UPLOADED_USING_UPLOAD_BUTTON;
import static nz.org.cacophony.birdmonitor.views.ManageRecordingsFragment.MessageType.SUCCESSFULLY_DELETED_RECORDINGS;
import static nz.org.cacophony.birdmonitor.views.ManageRecordingsFragment.MessageType.SUCCESSFULLY_UPLOADED_RECORDINGS_USING_UPLOAD_BUTTON;
import static nz.org.cacophony.birdmonitor.views.ManageRecordingsFragment.MessageType.UPLOADING_STOPPED;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.app.AlarmManager;
import android.app.Dialog;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.location.LocationManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Uri;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Environment;
import android.provider.Settings;
import android.text.SpannableString;
import android.text.TextUtils;
import android.text.method.LinkMovementMethod;
import android.text.util.Linkify;
import android.util.Base64;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.core.content.res.ResourcesCompat;

import com.google.firebase.crashlytics.FirebaseCrashlytics;
import com.luckycatlabs.SunriseSunsetCalculator;
import com.luckycatlabs.dto.Location;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.TimeZone;

import ch.qos.logback.classic.android.BasicLogcatConfigurator;
import kotlin.random.RandomKt;
import kotlin.ranges.IntRange;
import nz.org.cacophony.birdmonitor.views.MainActivity;

/**
 * A rather large set of helper methods that are placed here to simplify other
 * classes/methods.
 *
 * @author Tim Hunt
 */
public class Util {
    private static final String TAG = Util.class.getName();

    private static final String DEFAULT_RECORDINGS_FOLDER = "recordings";
    private static final String DEFAULT_RECORDING_NOTES_FOLDER = "notes";
    private static final String RECORDING_FILE_EXTENSION = ".m4a";

    private static final String COMMAND_AEROPLANE_RADIOS_BLUETOOTH = "settings put global airplane_mode_radios cell,wifi,nfc,wimax";
    private static final String COMMAND_AEROPLANE_RADIOS_DEFAULT = "settings put global airplane_mode_radios cell,wifi,nfc,wimax,bluetooth";

    // For airplane mode
    private final static String COMMAND_FLIGHT_MODE_1 = "settings put global airplane_mode_on";
    private final static String COMMAND_FLIGHT_MODE_2 = "am broadcast -a android.intent.action.AIRPLANE_MODE --ez state";

    static {
        BasicLogcatConfigurator.configureDefaultContext();
    }

    /**
     * Make sure user has given permission to record.
     */
    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    public static boolean checkPermissionsForRecording(Context context) {
        if (context == null) {
            Log.e(TAG, "Context was null when checking permissions");
            return false;
        }
        boolean canWriteExternalStorage = checkHasPermission(context, WRITE_EXTERNAL_STORAGE);
        boolean canRecordAudio = checkHasPermission(context, RECORD_AUDIO);
        boolean canAccessFineLocation = checkHasPermission(context, ACCESS_FINE_LOCATION);
        boolean canReadPhoneState = checkHasPermission(context, READ_PHONE_STATE);
        if (canWriteExternalStorage && canRecordAudio && canAccessFineLocation && canReadPhoneState) {
            return true;
        } else {
            Log.w(TAG, String.format("Missing permission for recording." +
                            "writeExternalStorage: %s, recordAudio: %s, accessFineLocation: %s, readPhoneState: %s",
                    canWriteExternalStorage, canRecordAudio, canAccessFineLocation, canReadPhoneState));
            return false;
        }
    }

    private static boolean checkHasPermission(Context context, String permission) {
        return ActivityCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED;
    }

    /**
     * Retrieve the location of where data is stored on the phone. Will
     * automatically use the sdcard
     * if it is present. This means for phones that do not have a internet
     * connection, you just
     * have to insert an sdcard and all recordings will be on the card, making it
     * possible to
     * retrieve the recordings by swapping out the card..
     *
     * @param context
     * @return Returns the location of where to store data on the phone
     */
    private static File getAppDataFolder(Context context) {

        // 15/8/16 Tim Hunt - Going to change file storage location to always use
        // internal phone storage rather than rely on sdcard
        // This is because if sdcard is 'dodgy' can get inconsistent results.
        // Need context to get internal storage location, so need to pass this around
        // the code.
        // If I could be sure the homeFile was set before any of the other directories
        // are needed then I
        // wouldn't need to pass context around to the other methods :-(

        File appDataFolder = null;
        String sDCardAvailable = isRemovableSDCardAvailable(context);
        if (sDCardAvailable == null) {
            Log.i(TAG, "No sd card detected");
        } else {
            Log.i(TAG, "sd card IS detected");
        }

        String canCreateFile = null;
        if (sDCardAvailable != null) {
            canCreateFile = canCreateFile(sDCardAvailable);
        }

        // https://developer.android.com/reference/android/content/Context.html#getDir(java.lang.String,
        // int)

        try {
            String appName = context.getResources().getString(R.string.activity_or_fragment_title_main);

            if (canCreateFile != null) {
                // Use the sdcard
                appDataFolder = new File(canCreateFile + "/" + appName);
                return appDataFolder;
            }

            String externalStorageState = Environment.getExternalStorageState();
            if (externalStorageState.equalsIgnoreCase("mounted")) {
                appDataFolder = new File(Environment.getExternalStorageDirectory().getAbsolutePath() + "/" + appName);
            } else {
                appDataFolder = context.getFilesDir();
            }

            if (appDataFolder != null) {
                if (!appDataFolder.exists()) {
                    boolean appDataFolderCreated = appDataFolder.mkdirs();
                    if (!appDataFolderCreated) {
                        return null;
                    }
                    // check it got created
                    if (!appDataFolder.exists()) {
                        return null;
                    }
                }
            }
        } catch (Exception ex) {
            Log.e(TAG, ex.getLocalizedMessage(), ex);
        }
        return appDataFolder;
    }

    /**
     * Returns the folder for storing recordings on the phone.
     *
     * @param context
     * @return File object representing recordings folder.
     */
    public static File getRecordingsFolder(Context context) {
        return getRecordingsOrNotesFolder(context, Util.DEFAULT_RECORDINGS_FOLDER);
    }

    /**
     * Returns the folder for storing recording notes on the phone.
     *
     * @param context
     * @return File object representing recording notes folder.
     */
    public static File getRecordingNotesFolder(Context context) {
        return getRecordingsOrNotesFolder(context, Util.DEFAULT_RECORDING_NOTES_FOLDER);
    }

    public static File getRecordingsOrNotesFolder(Context context, String recordingsOrNotes) {

        File localFolderFile;
        try {
            File appDataFolder = getAppDataFolder(context);
            if (appDataFolder == null) {

                return null;
            }

            localFolderFile = new File(appDataFolder, recordingsOrNotes);

            if (!localFolderFile.exists()) {
                localFolderFile.mkdirs();

                // now check it exists
                if (!localFolderFile.exists()) {
                    localFolderFile = null;
                }
            }

            // now check it is there

            if (localFolderFile == null) {
                Log.e(TAG, "There is a problem writing to the memory - please fix");
                getToast(context).show();
            }

            return localFolderFile;
        } catch (Exception ex) {
            Log.e(TAG, ex.getLocalizedMessage(), ex);
            getToast(context).show();
            return null;
        }
    }

    public static String getVersionName() {
        return BuildConfig.VERSION_NAME;
    }

    /**
     * Returns the device id of this phone. The device id has been allocated by the
     * server when
     * the phone registers with the server, and is stored locally in a 'webtoken'
     * string in the shared
     * preferences on this phone.
     *
     * @param webToken
     * @return
     * @throws Exception
     */
    public static long getDeviceID(String webToken) throws Exception {
        if (webToken == null) {
            return 0;
        }

        String webTokenBody = Util.decoded(webToken);
        JSONObject jObject = new JSONObject(webTokenBody);
        try {
            return Long.parseLong(jObject.getString("id"));
        } catch (NumberFormatException ex) {
            return 0;
        }
    }

    /**
     * Extracts the webtoken from the actual token
     *
     * @param JWTEncoded
     * @return
     */
    private static String decoded(String JWTEncoded) {
        // http://stackoverflow.com/questions/37695877/how-can-i-decode-jwt-token-in-android#38751017
        String webTokenBody = null;
        try {
            String[] split = JWTEncoded.split("\\.");
            webTokenBody = getJson(split[1]);
        } catch (UnsupportedEncodingException e) {
            Log.e(TAG, "Error decoding JWT");
        }
        return webTokenBody;
    }

    private static String getJson(String strEncoded) throws UnsupportedEncodingException {
        byte[] decodedBytes = Base64.decode(strEncoded, Base64.URL_SAFE);

        // https://www.tbray.org/ongoing/When/201x/2015/02/09/Silly-Java-Strings
        return new String(decodedBytes, "UTF8");
    }

    public static double getBatteryLevel(Context context) {
        double batteryLevel;
        batteryLevel = getBatteryLevelUsingSystemFile();
        if (batteryLevel == -1) {
            batteryLevel = getBatteryLevelByIntent(context);

        }
        return batteryLevel;
    }

    public static double getBatteryLevelUsingSystemFile() {

        // https://longtrieuquang.wordpress.com/2013/04/08/android-battery-information-from-file-system/
        // found the file volt that stores battery voltage
        String batteryLevelStr = null;
        double batteryLevel = -1;
        String voltFilePathName = "/sys/class/power_supply/battery/volt";
        File voltFile = new File(voltFilePathName);
        if (voltFile.exists()) {
            try {
                batteryLevelStr = getStringFromFile(voltFilePathName);
            } catch (Exception ex) {
                ex.printStackTrace();

                Log.e(TAG, ex.getLocalizedMessage(), ex);
            }
        }

        if (batteryLevelStr != null) {
            try {
                batteryLevel = Double.parseDouble(batteryLevelStr);
            } catch (Exception ex) {
                Log.e(TAG, "converting double");
            }
        }
        return batteryLevel;
    }

    public static double getBatteryLevelByIntent(Context context) {

        // Will use the method of checking battery level that may only give an update if
        // phone charging status changes
        // this will return a percentage
        try {
            double batteryLevel;
            IntentFilter ifilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
            Intent batteryStatus = context.getApplicationContext().registerReceiver(null, ifilter);
            batteryLevel = batteryStatus != null ? batteryStatus.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) : -1;
            return batteryLevel;
        } catch (Exception ex) {
            Log.e(TAG, "Error with getBatteryLevelByIntent");
            return -1;
        }
    }

    private static String getStringFromFile(String filePath) throws Exception {
        File fl = new File(filePath);
        FileInputStream fin = new FileInputStream(fl);
        String ret = convertStreamToString(fin);

        // Make sure you close all streams.
        fin.close();
        return ret;
    }

    private static String convertStreamToString(InputStream is) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        String line;
        line = reader.readLine();
        reader.close();
        return line;
    }

    public static String getBatteryStatus(Context context) {
        // https://developer.android.com/training/monitoring-device-state/battery-monitoring.html
        // http://stackoverflow.com/questions/24934260/intentreceiver-components-are-not-allowed-to-register-to-receive-intents-when

        try {
            IntentFilter ifilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
            Intent batteryStatus = context.getApplicationContext().registerReceiver(null, ifilter);
            // Are we charging / charged?
            int status = batteryStatus != null ? batteryStatus.getIntExtra(BatteryManager.EXTRA_STATUS, -1) : -1;

            String batteryStatusToReturn;
            switch (status) {
                case BatteryManager.BATTERY_STATUS_CHARGING:
                    batteryStatusToReturn = "CHARGING";
                    break;
                case BatteryManager.BATTERY_STATUS_DISCHARGING:
                    batteryStatusToReturn = "DISCHARGING";
                    break;
                case BatteryManager.BATTERY_STATUS_NOT_CHARGING:
                    batteryStatusToReturn = "NOT_CHARGING";
                    break;
                case BatteryManager.BATTERY_STATUS_FULL:
                    batteryStatusToReturn = "FULL";
                    break;
                case BatteryManager.BATTERY_STATUS_UNKNOWN:
                    batteryStatusToReturn = "UNKNOWN";
                    break;
                default:
                    batteryStatusToReturn = Integer.toString(status);
            }
            return batteryStatusToReturn;
        } catch (Exception ex) {
            Log.e(TAG, "getBatteryStatus");
            return "Error";
        }

    }

    /**
     * Gets the state of Airplane Mode.
     * http://stackoverflow.com/questions/4319212/how-can-one-detect-airplane-mode-on-android
     *
     * @return true if enabled.
     */
    @SuppressWarnings("deprecation")
    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR1)
    public static boolean isAirplaneModeOn(Context context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR1) {
            return Settings.System.getInt(context.getContentResolver(),
                    Settings.System.AIRPLANE_MODE_ON, 0) != 0;
        } else {
            return Settings.Global.getInt(context.getContentResolver(),
                    Settings.Global.AIRPLANE_MODE_ON, 0) != 0;
        }
    }

    /**
     * Returns the sunrise time for the current device location
     *
     * @param context - for getting the location
     * @return Calendar time of the sunrise
     */
    private static Calendar getSunrise(Context context, Calendar todayOrTomorrow) {

        Location location = getLocation(context);
        SunriseSunsetCalculator calculator = new SunriseSunsetCalculator(location, "Pacific/Auckland");
        return calculator.getOfficialSunriseCalendarForDate(todayOrTomorrow);
    }

    public static Calendar getNoon(Context context, Calendar todayOrTomorrow) {
        Calendar sunrise = getSunrise(context, todayOrTomorrow);
        Calendar sunset = getSunset(context, todayOrTomorrow);
        long noonMillis = (sunrise.getTimeInMillis() + sunset.getTimeInMillis()) / 2;
        Calendar cal = GregorianCalendar.getInstance();
        cal.setTimeInMillis(noonMillis);
        return cal;
    }

    public static Calendar getDawn(Context context, Calendar todayOrTomorrow) {
        Prefs prefs = new Prefs(context);
        Calendar sunRise = getSunrise(context, todayOrTomorrow);
        Calendar dawn = (Calendar) sunRise.clone();
        int lengthOfTwilight = (int) prefs.getLengthOfTwilightSeconds();
        dawn.add(Calendar.SECOND, -lengthOfTwilight);
        return dawn;
    }

    /**
     * Returns the sunset time for the current device location
     *
     * @param context - for getting the location
     * @return Calendar time of the sunset
     */
    private static Calendar getSunset(Context context, Calendar todayOrTomorrow) {

        Location location = getLocation(context);
        SunriseSunsetCalculator calculator = new SunriseSunsetCalculator(location, "Pacific/Auckland");
        return calculator.getOfficialSunsetCalendarForDate(todayOrTomorrow);
    }

    /**
     * Returns the dusk time for the current location
     *
     * @param context
     * @param todayOrTomorrow Calendar that represents either today or tomorrow
     * @return
     */
    public static Calendar getDusk(Context context, Calendar todayOrTomorrow) {
        Prefs prefs = new Prefs(context);
        Calendar sunSet = getSunset(context, todayOrTomorrow);
        Calendar dusk = (Calendar) sunSet.clone();
        int lengthOfTwilight = (int) prefs.getLengthOfTwilightSeconds();
        dusk.add(Calendar.SECOND, lengthOfTwilight);
        return dusk;
    }

    private static Location getLocation(Context context) {
        Prefs prefs = new Prefs(context);
        String lat;
        String lon;

        if (prefs.getLatitude() == 0.0 && prefs.getLongitude() == 0.0) {
            // gps not yet set, so to avoid errors/too complex code to check, just use
            // coordinates for Hamilton NZ
            lat = Double.toString(-37.805294);
            lon = Double.toString(175.306775);

        } else {
            lat = Double.toString(prefs.getLatitude());
            lon = Double.toString(prefs.getLongitude());
        }

        return new Location(lat, lon);
    }

    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    public static boolean waitForNetworkConnection(Context context, boolean networkConnectionRequired) {
        int numberOfLoops = 0;
        boolean connected = isNetworkConnected(context);
        while (!connected && networkConnectionRequired) {
            try {
                Thread.sleep(1000); // give time for airplane mode to turn off
            } catch (InterruptedException ex) {
                Log.e(TAG, ex.getLocalizedMessage());
            }

            numberOfLoops += 1;
            if (numberOfLoops > 60) {
                Log.e(TAG, "Number of loops > 60");
                break;
            }
            connected = isNetworkConnected(context);
        }
        return connected;
    }

    public static boolean isNetworkConnected(Context context) {

        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) {
            Log.e(TAG, "cm is null");
            return false; // false may not be correct
        }

        NetworkInfo activeNetwork = cm.getActiveNetworkInfo();
        @SuppressWarnings("UnnecessaryLocalVariable")
        boolean isConnected = activeNetwork != null &&
                activeNetwork.isConnectedOrConnecting();
        // if (!rootedIdlingResource.isIdleNow()){
        // rootedIdlingResource.decrement();
        // }
        return isConnected;
    }

    public static void setAeroplaneBluetooth(final Context context, boolean enable) {
        if (enable) {
            executeCommandTim(context, COMMAND_AEROPLANE_RADIOS_BLUETOOTH);
        } else {
            executeCommandTim(context, COMMAND_AEROPLANE_RADIOS_DEFAULT);
        }
    }

    public static void rebootNow(final Context context) {
        executeCommandTim(context, "reboot");
    }

    public static void disableFlightMode(final Context context) {
        disableFlightMode(context, 0);
    }

    public static void disableFlightMode(final Context context, int flags) {
        Prefs prefs = new Prefs(context);
        if (!prefs.getAeroplaneMode()) {
            return;
        }
        if (flags > 0) {
            prefs.setInternetRequired(true, flags);
        }
        new Thread(() -> {
            try {
                if (Build.VERSION.SDK_INT > Build.VERSION_CODES.JELLY_BEAN) {
                    // API 17 onwards.
                    // Must be a rooted device
                    if (!prefs.getHasRootAccess()) { // don't try to disable flight mode if phone has been rooted.
                        return;
                    }

                    if (prefs.getInternetConnectionMode().equalsIgnoreCase("offline")) { // Don't try to turn on aerial
                        // if set to be offline
                        return;
                    }

                    // Set Airplane / Flight mode using su commands.
                    String command = COMMAND_FLIGHT_MODE_1 + " " + "0";
                    executeCommandTim(context, command);
                    command = COMMAND_FLIGHT_MODE_2 + " " + "false";
                    executeCommandTim(context, command);

                } else {
                    // API 16 and earlier.

                    // noinspection deprecation
                    Settings.System.putInt(context.getContentResolver(), Settings.System.AIRPLANE_MODE_ON, 0);
                    Intent intent = new Intent(Intent.ACTION_AIRPLANE_MODE_CHANGED);
                    intent.putExtra("state", false);
                    context.sendBroadcast(intent);
                }

            } catch (Exception ex) {
                FirebaseCrashlytics.getInstance().recordException(ex);
                Log.e(TAG, ex.getLocalizedMessage(), ex);
            }

        }).start();
        // rootedIdlingResource.increment(); // and decrement in isNetworkConnected
        // method
    }

    public static void relaunch(final Context context) {
        Intent intent = new Intent(context, MainActivity.class);
        int mPendingIntentId = 1;
        PendingIntent mPendingIntent = PendingIntent.getActivity(context, mPendingIntentId, intent,
                PendingIntent.FLAG_CANCEL_CURRENT);
        AlarmManager mgr = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
        mgr.set(AlarmManager.RTC, System.currentTimeMillis() + 1000, mPendingIntent);
    }

    public static void enableFlightMode(final Context context) {
        Prefs prefs = new Prefs(context);
        if (!new Prefs(context).getAeroplaneMode()) {
            return;
        }

        if (prefs.getOnlineMode() || Util.isAirplaneModeOn(context)) {
            return;
        }

        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.JELLY_BEAN) { // Jelly bean is 4.1

            // API 17 onwards.
            // Must be a rooted device

            if (!prefs.getHasRootAccess()) {
                Log.e(TAG, "Do NOT have required ROOT access");
                return;
            }
        }

        if (UpdateUtil.isDownloading(context)) {
            Log.d(TAG, "Flight mode pending as am downloading update");
            prefs.setInternetRequired(true, Prefs.FLIGHT_MODE_PENDING_UPDATE);
            return;
        }
        if (prefs.getFlightModePending() > 0) {
            Log.d(TAG, "Flight mode pending status: " + prefs.getFlightModePending());
            return;
        }
        new Thread(() -> {
            try {
                if (Build.VERSION.SDK_INT > Build.VERSION_CODES.JELLY_BEAN) { // Jelly bean is 4.1

                    // Set Airplane / Flight mode using su commands.
                    String command = COMMAND_FLIGHT_MODE_1 + " " + "1";
                    executeCommandTim(context, command);
                    command = COMMAND_FLIGHT_MODE_2 + " " + "true";
                    executeCommandTim(context, command);
                    // rootedIdlingResource.decrement();

                } else {

                    // noinspection deprecation
                    Settings.System.putInt(context.getContentResolver(), Settings.System.AIRPLANE_MODE_ON, 1);
                    Intent intent = new Intent(Intent.ACTION_AIRPLANE_MODE_CHANGED);
                    intent.putExtra("state", true);
                    context.sendBroadcast(intent);
                }

            } catch (Exception e) {
                Log.e(TAG, "Error disabling flight mode");
            }

        }).start();
    }

    private static void executeCommandTim(Context context, String command) {
        try {
            ExecuteAsRootBaseTim executeAsRootBaseTim = new ExecuteAsRootBaseTim();
            executeAsRootBaseTim.addCommand(command);
            executeAsRootBaseTim.execute(context);
        } catch (Exception ex) {
            Log.e(TAG, ex.getLocalizedMessage(), ex);
            MessageHelper.broadcastMessage("error", ERROR_DO_NOT_HAVE_ROOT, ROOT_ACTION, context);
        }
    }

    public static String getSimStateAsString(int simState) {
        String simStateStr;
        switch (simState) {
            case 0:
                simStateStr = "SIM_STATE_UNKNOWN";
                break;
            case 1:
                simStateStr = "SIM_STATE_ABSENT";
                break;
            case 2:
                simStateStr = "SIM_STATE_PIN_REQUIRED";
                break;
            case 3:
                simStateStr = "SIM_STATE_PUK_REQUIRED";
                break;
            case 4:
                simStateStr = "SIM_STATE_NETWORK_LOCKED";
                break;
            case 5:
                simStateStr = "SIM_STATE_READY";
                break;
            case 6:
                simStateStr = "SIM_STATE_NOT_READY";
                break;
            case 7:
                simStateStr = "SIM_STATE_PERM_DISABLED";
                break;
            case 8:
                simStateStr = "SIM_STATE_CARD_IO_ERROR";
                break;
            case 9:
                simStateStr = "SIM_STATE_CARD_RESTRICTED";
                break;
            case 10:
                simStateStr = "October";
                break;
            case 11:
                simStateStr = "November";
                break;
            case 12:
                simStateStr = "December";
                break;
            default:
                simStateStr = "noMatch";
                break;
        }
        return simStateStr;
    }

    public static Toast getToast(Context context) {
        @SuppressLint("ShowToast")
        Toast toast = Toast.makeText(context, "There is a problem writing to the memory - please fix",
                Toast.LENGTH_LONG);
        toast.getView().setBackgroundColor(context.getResources().getColor(R.color.alert));
        return toast;
    }

    // https://stackoverflow.com/questions/5694933/find-an-external-sd-card-location/29107397#29107397
    private static String isRemovableSDCardAvailable(Context context) {
        final String FLAG = "mnt";
        final String SECONDARY_STORAGE = System.getenv("SECONDARY_STORAGE");
        final String EXTERNAL_STORAGE_DOCOMO = System.getenv("EXTERNAL_STORAGE_DOCOMO");
        final String EXTERNAL_SDCARD_STORAGE = System.getenv("EXTERNAL_SDCARD_STORAGE");
        final String EXTERNAL_SD_STORAGE = System.getenv("EXTERNAL_SD_STORAGE");
        final String EXTERNAL_STORAGE = System.getenv("EXTERNAL_STORAGE");

        @SuppressLint("UseSparseArrays")
        Map<Integer, String> listEnvironmentVariableStoreSDCardRootDirectory = new HashMap<>();
        listEnvironmentVariableStoreSDCardRootDirectory.put(0, SECONDARY_STORAGE);
        listEnvironmentVariableStoreSDCardRootDirectory.put(1, EXTERNAL_STORAGE_DOCOMO);
        listEnvironmentVariableStoreSDCardRootDirectory.put(2, EXTERNAL_SDCARD_STORAGE);
        listEnvironmentVariableStoreSDCardRootDirectory.put(3, EXTERNAL_SD_STORAGE);
        listEnvironmentVariableStoreSDCardRootDirectory.put(4, EXTERNAL_STORAGE);

        File[] externalStorageList = null;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.KITKAT) {
            externalStorageList = context.getExternalFilesDirs(null);
        }
        String directory;
        int size = listEnvironmentVariableStoreSDCardRootDirectory.size();
        for (int i = 0; i < size; i++) {
            if (externalStorageList != null && externalStorageList.length >= 1 && externalStorageList[0] != null)
                directory = externalStorageList[0].getAbsolutePath();
            else
                directory = listEnvironmentVariableStoreSDCardRootDirectory.get(i);

            directory = canCreateFile(directory);
            if (directory != null && directory.length() != 0) {
                if (i == size - 1) {
                    if (directory.contains(FLAG)) {
                        return directory;
                    } else {
                        return null;
                    }
                }

                return directory;
            }
        }
        return null;
    }

    private static String canCreateFile(String directory) {
        // https://stackoverflow.com/questions/5694933/find-an-external-sd-card-location
        final String FILE_DIR = directory + File.separator + "hoang.txt";
        File tempFile = null;
        try {
            tempFile = new File(FILE_DIR);
            FileOutputStream fos = new FileOutputStream(tempFile);
            fos.write(new byte[1024]);
            fos.flush();
            fos.close();

        } catch (Exception e) {
            return null;
        } finally {
            if (tempFile != null && tempFile.exists() && tempFile.isFile()) {
                // noinspection UnusedAssignment
                tempFile = null;
            }
        }
        return directory;
    }

    public static boolean isWebTokenCurrent(Prefs prefs) {
        if (prefs.getToken() == null) {
            return false;
        }
        long currentTimeMilliSeconds = new Date().getTime();
        long tokenLastRefreshedMilliSeconds = prefs.getTokenLastRefreshed();
        long tokenTimeOutSeconds = Prefs.getDeviceTokenTimeoutSeconds();
        long tokenTimeOutMilliSeconds = tokenTimeOutSeconds * 1000;
        if ((currentTimeMilliSeconds - tokenLastRefreshedMilliSeconds) > tokenTimeOutMilliSeconds) {
            prefs.setDeviceToken(null);
            Log.d(TAG, "Web token out of date and so set to null");
            return false;
        } else {
            return true;
        }
    }

    public static void setAlarmManagerWakeUp(AlarmManager alarmManager, long wakeUpTime, PendingIntent pendingIntent) {
        // https://developer.android.com/reference/android/app/AlarmManager.html

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT) { // KitKat is 19
            alarmManager.set(AlarmManager.RTC_WAKEUP, wakeUpTime, pendingIntent);
            return;
        }

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) { // m is Marshmallow 23
            int windowSize = 1000 * 60 * 2;
            alarmManager.setWindow(AlarmManager.RTC_WAKEUP, wakeUpTime - windowSize, windowSize * 2, pendingIntent);
            return;
        }

        // Marshmallow will go into Doze mode, so use setExactAndAllowWhileIdle to allow
        // wakeup
        // https://developer.android.com/reference/android/app/AlarmManager#setExactAndAllowWhileIdle(int,%20long,%20android.app.PendingIntent)
        alarmManager.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, wakeUpTime, pendingIntent);
    }

    public static void createFailSafeAlarm(Context context) { // Each alarm creates the next one, need to have this fail
        // safe to get them going again (it doesn't rely on a
        // previous alarm)
        Intent myIntent = new Intent(context, StartRecordingReceiver.class);
        try {
            myIntent.putExtra(Prefs.INTENT_TYPE, Prefs.FAIL_SAFE_ALARM);
            Uri timeUri; // // this will hopefully allow matching of intents so when adding a new one
            // with new time it will replace this one
            timeUri = Uri.parse(Prefs.FAIL_SAFE_ALARM); // cf dawn dusk offsets created in DawnDuskAlarms
            myIntent.setData(timeUri);

        } catch (Exception ex) {
            Log.e(TAG, ex.getLocalizedMessage(), ex);
        }

        PendingIntent pendingIntent = PendingIntent.getBroadcast(context, 0, myIntent, 0);

        AlarmManager alarmManager = (AlarmManager) context.getSystemService(ALARM_SERVICE);
        if (alarmManager == null) {
            Log.e(TAG, "alarmManager is null");
            return;
        }

        alarmManager.setInexactRepeating(AlarmManager.ELAPSED_REALTIME_WAKEUP, AlarmManager.INTERVAL_FIFTEEN_MINUTES,
                AlarmManager.INTERVAL_DAY, pendingIntent);
    }

    // Get the next sunrise/noon/sunset alarm closest to the current time
    public static Alarm getClosestSunAlarm(Context context, Prefs prefs) {
        Calendar calNow = new GregorianCalendar(TimeZone.getTimeZone("Pacific/Auckland"));

        long wakeUpTime = System.currentTimeMillis();
        long offset = getSunrise(context, calNow).getTimeInMillis() + prefs.getSunriseOffsetMillis();
        if (offset > wakeUpTime) {
            return new Alarm(offset, Prefs.SUNRISE_OFFSET);
        }
        offset = getNoon(context, calNow).getTimeInMillis() + prefs.getNoonOffsetMillis();
        if (offset > wakeUpTime) {
            return new Alarm(offset, Prefs.NOON_OFFSET);
        }
        offset = getSunset(context, calNow).getTimeInMillis() + prefs.getSunsetOffsetMillis();
        if (offset > wakeUpTime) {
            return new Alarm(offset, Prefs.SUNSET_OFFSET);
        }
        calNow.add(Calendar.DAY_OF_YEAR, 1);
        offset = getSunrise(context, calNow).getTimeInMillis() + prefs.getSunriseOffsetMillis();
        return new Alarm(offset, Prefs.SUNRISE_OFFSET);
    }

    public static Alarm getNextAlarm(Context context, Prefs prefs, String curOffset) {
        long wakeUpTime;
        if (prefs.getUseSunAlarms()) {
            Calendar calNow = new GregorianCalendar(TimeZone.getTimeZone("Pacific/Auckland"));
            Alarm alarm;
            if (curOffset == null || curOffset.equals(Prefs.FAIL_SAFE_ALARM)) {
                alarm = getClosestSunAlarm(context, prefs);
            } else {
                switch (curOffset) {
                    case Prefs.SUNRISE_OFFSET:
                        wakeUpTime = getNoon(context, calNow).getTimeInMillis() + prefs.getNoonOffsetMillis();
                        alarm = new Alarm(wakeUpTime, Prefs.NOON_OFFSET);
                        break;
                    case Prefs.NOON_OFFSET:
                        wakeUpTime = getSunset(context, calNow).getTimeInMillis() + prefs.getSunsetOffsetMillis();
                        alarm = new Alarm(wakeUpTime, Prefs.SUNSET_OFFSET);
                        break;
                    case Prefs.SUNSET_OFFSET:
                        calNow.add(Calendar.DAY_OF_YEAR, 1);
                        wakeUpTime = getSunrise(context, calNow).getTimeInMillis() + prefs.getSunriseOffsetMillis();
                        alarm = new Alarm(wakeUpTime, Prefs.SUNRISE_OFFSET);
                        break;
                    default:
                        alarm = getClosestSunAlarm(context, prefs);
                        break;
                }
            }
            return alarm;
        } else {
            wakeUpTime = System.currentTimeMillis();
            if (prefs.getUseVeryFrequentRecordings()) {
                return new Alarm(wakeUpTime + 1000 * (long) prefs.getTimeBetweenVeryFrequentRecordingsSeconds(), Prefs.NORMAL_URI);
            }
            if (prefs.getRandomSeed() > 9999) {
                int seed = new Random().nextInt(9999);
                prefs.setRandomSeed(seed);
            }

            String seed = String.valueOf(prefs.getRandomSeed());
            long currentDayInMillis = wakeUpTime / (1000 * 60 * 60 * 24) * (1000 * 60 * 60 * 24);

            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                seed += LocalDate.now().getDayOfMonth();
                seed += LocalDate.now().getMonthValue();
            } else {
                seed += currentDayInMillis;
            }

            // Ensure seed is within 32-bit integer bounds
            try {
                long seedLong = Long.parseLong(seed);
                seedLong = Math.max(Integer.MIN_VALUE, Math.min(seedLong, Integer.MAX_VALUE));
                int randomSeed = (int) seedLong;
                prefs.setRandomSeed(randomSeed);

                Random chance = new Random(randomSeed);
                while (currentDayInMillis < wakeUpTime) {
                    float toWakeUp = chance.nextFloat();
                    float randomTime = chance.nextFloat();
                    float inXMinutes = (toWakeUp < prefs.getshortRecordingWindowChance())
                            ? (prefs.getShortRecordingPause() + randomTime * prefs.getShortRecordingWindowMinutes())
                            : (prefs.getLongRecordingPause() + randomTime * prefs.getLongRecordingWindowMinutes());
                    currentDayInMillis += (long) (1000 * 60 * inXMinutes);
                }
                wakeUpTime = currentDayInMillis;
            } catch (NumberFormatException e) {
                Log.e(TAG, "Error parsing seed to long: " + e.getMessage());
                wakeUpTime = System.currentTimeMillis() + 1000 * 60 * 5; // fallback to a 5-minute delay
            }
        }
        // log the time of the next alarm
        Log.i(TAG, "Next alarm is at " + new Date(wakeUpTime));
        return new Alarm(wakeUpTime, Prefs.NORMAL_URI);
    }


    public static Intent getRepeatingAlarmIntent(Context context, String relativeTo) {
        Intent intent = new Intent(context, StartRecordingReceiver.class);
        intent.putExtra(Prefs.INTENT_TYPE, Prefs.REPEATING_ALARM);
        intent.setData(Uri.parse(Prefs.NORMAL_URI));
        if (relativeTo != null) {
            intent.putExtra(Prefs.RELATIVE, relativeTo);
        }
        return intent;
    }

    public static boolean alarmExists(Context context) {
        return PendingIntent.getBroadcast(context, 0, getRepeatingAlarmIntent(context, null),
                PendingIntent.FLAG_NO_CREATE | PendingIntent.FLAG_IMMUTABLE) != null;
    }

    /**
     * Creates Android OS alarms that when fired by the OS, create and send intents
     * to the
     * StartRecordingReceiver class which in turn initiate a recording.
     * <p>
     * There is also a method called createCreateAlarms that kick starts this
     * method.
     *
     * @param context *
     */
    public static void createTheNextSingleStandardAlarm(Context context, String relativeTo, String triggerType) {
        Prefs prefs = new Prefs(context);
        Alarm nextAlarm = getNextAlarm(context, prefs, relativeTo);
        Intent myIntent = getRepeatingAlarmIntent(context, nextAlarm.OffsetType);
        AlarmManager alarmManager = (AlarmManager) context.getSystemService(ALARM_SERVICE);
        if (alarmManager == null) {
            Log.e(TAG, "alarmManager is null");
            return;
        }

        boolean updateTime = (triggerType != null && triggerType.equals(Prefs.REPEATING_ALARM))
                || !alarmExists(context);
        int flags = 0;
        if (prefs.getUseSunAlarms()) {
            flags = PendingIntent.FLAG_UPDATE_CURRENT;
        }
        PendingIntent pendingIntent = PendingIntent.getBroadcast(context, 0, myIntent, flags);
        setAlarmManagerWakeUp(alarmManager, nextAlarm.TimeMillis, pendingIntent);
        if (updateTime || prefs.getUseSunAlarms()) {
            prefs.setTheNextSingleStandardAlarmUsingUnixTime(nextAlarm.TimeMillis);
        }
    }

    public static void updateGPSLocation(Context context) {
        LocationManager locationManager = (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
        if (locationManager == null) {
            Log.e(TAG, "locationManager is null");
            return;
        }

        // https://stackoverflow.com/questions/36123431/gps-service-check-to-check-if-the-gps-is-enabled-or-disabled-on-device
        if (!locationManager.isProviderEnabled(LocationManager.GPS_PROVIDER)) {
            String messageToDisplay = "Sorry, GPS is not enabled.  Please enable location/gps in the phone settings and try again.";
            MessageHelper.broadcastMessage(messageToDisplay, GPS_UPDATE_FAILED, GPS_ACTION, context);
            return;
        }

        GPSLocationListener gpsLocationListener = new GPSLocationListener(context);
        try {
            locationManager.requestSingleUpdate(LocationManager.GPS_PROVIDER, gpsLocationListener,
                    context.getMainLooper());

        } catch (SecurityException e) {
            Log.e(TAG, "Unable to get GPS location. Don't have required permissions.");

        }
    }

    public static String getNextAlarm(Context context) {
        Prefs prefs = new Prefs(context);
        long nextAlarm = prefs.getNextSingleStandardAlarm();
        return convertUnixTimeToString(nextAlarm);
    }

    public static String getTimeThatLastRecordingHappened(Context context) {
        Prefs prefs = new Prefs(context);
        long lastRecordingTime = prefs.getTimeThatLastRecordingHappened();
        return convertUnixTimeToString(lastRecordingTime);
    }

    public static void setTimeThatLastRecordingHappened(Context context,
                                                        long timeLastRecordingHappened) {
        Prefs prefs = new Prefs(context);
        prefs.setTimeThatLastRecordingHappened(timeLastRecordingHappened);
    }

    public static String convertUnixTimeToString(long unixTimeToConvert) {
        if (unixTimeToConvert < 1) {
            return "";
        }
        Date date = new Date(unixTimeToConvert);
        Locale nzLocale = new Locale("nz");
        DateFormat fileFormat = new SimpleDateFormat("EEE, d MMM yyyy 'at' HH:mm:ss", nzLocale);
        return fileFormat.format(date);
    }

    public static void setUseVeryFrequentRecordings(Context context,
                                                    boolean useVeryFrequentRecordings) {
        Prefs prefs = new Prefs(context);
        prefs.setUseVeryFrequentRecordings(useVeryFrequentRecordings);
        changeAlarmType(context);
    }

    public static void setUseFrequentUploads(Context context, boolean useFrequentUploads) {
        Prefs prefs = new Prefs(context);
        prefs.setUseFrequentUploads(useFrequentUploads);

    }

    public static void uploadFilesUsingUploadButton(final Context context) {
        new Thread(() -> {
            try {
                boolean uploadedSuccessfully = RecordAndUpload.uploadFiles(context);
                if (RecordAndUpload.isCancelUploadingRecordings()) {
                    String messageToDisplay = "Uploading of recordings has been stopped";
                    MessageHelper.broadcastMessage(messageToDisplay, UPLOADING_STOPPED, MANAGE_RECORDINGS_ACTION,
                            context);
                } else if (uploadedSuccessfully) {
                    Log.i(TAG, "Upload complete");
                    String messageToDisplay = "Recordings have been uploaded to the server.";
                    MessageHelper.broadcastMessage(messageToDisplay,
                            SUCCESSFULLY_UPLOADED_RECORDINGS_USING_UPLOAD_BUTTON, MANAGE_RECORDINGS_ACTION, context);
                } else {
                    String messageToDisplay = "There was a problem. The recordings were NOT uploaded.";
                    MessageHelper.broadcastMessage(messageToDisplay, FAILED_RECORDINGS_NOT_UPLOADED_USING_UPLOAD_BUTTON,
                            MANAGE_RECORDINGS_ACTION, context);
                }
            } catch (Exception ex) {
                Log.e(TAG, ex.getLocalizedMessage(), ex);
            }
        }).start();
    }

    public static void displayHelp(final Context context, String activityOrFragmentName) {

        String dialogMessage;

        if (activityOrFragmentName.equalsIgnoreCase(context.getResources().getString(R.string.app_icon_name))) {
            dialogMessage = context.getString(R.string.help_text_welcome);
        } else if (activityOrFragmentName
                .equalsIgnoreCase(context.getResources().getString(R.string.activity_or_fragment_title_welcome))) {
            dialogMessage = context.getString(R.string.help_text_welcome);
        } else if (activityOrFragmentName.equalsIgnoreCase(
                context.getResources().getString(R.string.activity_or_fragment_title_create_account))) {
            dialogMessage = context.getString(R.string.help_text_create_account);
        } else if (activityOrFragmentName
                .equalsIgnoreCase(context.getResources().getString(R.string.activity_or_fragment_title_sign_in))) {
            dialogMessage = context.getString(R.string.help_text_sign_in);
        } else if (activityOrFragmentName.equalsIgnoreCase(
                context.getResources().getString(R.string.activity_or_fragment_title_create_or_choose_group))) {
            dialogMessage = context.getString(R.string.help_text_create_or_choose_group);
        } else if (activityOrFragmentName.equalsIgnoreCase(
                context.getResources().getString(R.string.activity_or_fragment_title_register_phone))) {
            dialogMessage = context.getString(R.string.help_text_register_phone);
        } else if (activityOrFragmentName
                .equalsIgnoreCase(context.getResources().getString(R.string.activity_or_fragment_title_gps_location))) {
            dialogMessage = context.getString(R.string.help_text_gps_location);
        } else if (activityOrFragmentName
                .equalsIgnoreCase(context.getResources().getString(R.string.activity_or_fragment_title_test_record))) {
            dialogMessage = context.getString(R.string.help_text_test_record);
        } else if (activityOrFragmentName
                .equalsIgnoreCase(context.getResources().getString(R.string.activity_or_fragment_title_vitals))) {
            dialogMessage = context.getString(R.string.help_text_vitals);
        } else if (activityOrFragmentName
                .equalsIgnoreCase(context.getResources().getString(R.string.activity_or_fragment_title_walking))) {
            dialogMessage = context.getString(R.string.help_text_walking);
        } else if (activityOrFragmentName.equalsIgnoreCase(
                context.getResources().getString(R.string.activity_or_fragment_title_activity_ignore_low_battery))) {
            dialogMessage = context.getString(R.string.help_text_battery);
        } else if (activityOrFragmentName.equalsIgnoreCase(
                context.getResources().getString(R.string.activity_or_fragment_title_warning_sound))) {
            dialogMessage = context.getString(R.string.help_text_warning_sound);
        } else if (activityOrFragmentName.equalsIgnoreCase(
                context.getResources().getString(R.string.activity_or_fragment_title_manage_recordings))) {
            dialogMessage = context.getString(R.string.help_text_manage_recordings);
        } else if (activityOrFragmentName.equalsIgnoreCase(
                context.getResources().getString(R.string.activity_or_fragment_title_internet_connection))) {
            dialogMessage = context.getString(R.string.help_text_internet_connection);
        } else if (activityOrFragmentName.equalsIgnoreCase(
                context.getResources().getString(R.string.activity_or_fragment_title_activity_frequency))) {
            dialogMessage = context.getString(R.string.help_text_frequency);
        } else if (activityOrFragmentName
                .equalsIgnoreCase(context.getResources().getString(R.string.activity_or_fragment_title_rooted))) {
            dialogMessage = context.getString(R.string.help_text_rooted);
        } else if (activityOrFragmentName.equalsIgnoreCase(
                context.getResources().getString(R.string.activity_or_fragment_title_settings_for_testing))) {
            dialogMessage = context.getString(R.string.help_text_settings_for_testing);
        } else if (activityOrFragmentName.equalsIgnoreCase(
                context.getResources().getString(R.string.activity_or_fragment_title_turn_off_or_on))) {
            dialogMessage = context.getString(R.string.help_text_turn_off_or_on);
        } else if (activityOrFragmentName.equalsIgnoreCase(
                context.getResources().getString(R.string.activity_or_fragment_title_settings_for_audio_source))) {
            dialogMessage = context.getString(R.string.help_text_settings_for_audio_source);
        } else if (activityOrFragmentName
                .equalsIgnoreCase(context.getResources().getString(R.string.activity_or_fragment_title_bird_count))) {
            dialogMessage = context.getString(R.string.help_text_settings_for_bird_count);
        } else if (activityOrFragmentName.equalsIgnoreCase(
                context.getResources().getString(R.string.activity_or_fragment_title_activity_sun_alarms))) {
            dialogMessage = context.getString(R.string.help_text_settings_for_sun_alarms);
        } else {
            dialogMessage = "Still to fix in Util.displayHelp";
        }

        // Make any urls 'clickable'
        // https://stackoverflow.com/questions/9204303/android-is-it-possible-to-add-a-clickable-link-into-a-string-resource
        final SpannableString s = new SpannableString(dialogMessage);

        Linkify.addLinks(s, Linkify.ALL);

        final AlertDialog dialog = new AlertDialog.Builder(context)
                .setPositiveButton("OK", (di, id) -> {
                    /* Exit the dialog */
                })
                .setMessage(s)
                .setTitle(activityOrFragmentName)
                .create();

        // https://stackoverflow.com/questions/15909672/how-to-set-font-size-for-text-of-dialog-buttons
        dialog.setOnShowListener(dialogInterface -> {
            Button btnPositive = dialog.getButton(Dialog.BUTTON_POSITIVE);
            btnPositive.setTextSize(24);
            int oKButtonColor = ResourcesCompat.getColor(context.getResources(), R.color.dialogButtonText, null);
            btnPositive.setTextColor(oKButtonColor);

            // https://stackoverflow.com/questions/6562924/changing-font-size-into-an-alertdialog
            // https://stackoverflow.com/questions/13520193/android-linkify-how-to-set-custom-link-color
            TextView textView = dialog.findViewById(android.R.id.message);
            int linkColorInt = ResourcesCompat.getColor(context.getResources(), R.color.linkToServerInHelp, null);
            textView.setLinkTextColor(linkColorInt);
            textView.setTextSize(22);
        });

        dialog.setCancelable(true);
        dialog.setCanceledOnTouchOutside(true);

        dialog.show();

        // Make the textview clickable. Must be called after show(). Need for URL to
        // work
        ((TextView) dialog.findViewById(android.R.id.message)).setMovementMethod(LinkMovementMethod.getInstance());
    }

    public static void deleteAllRecordingsOnPhoneUsingDeleteButton(final Context context) {
        if (RecordAndUpload.isRecording) {
            new Prefs(context).setCancelRecording(true);
        }
        new Thread(() -> {
            try {
                File recordingsFolder = Util.getRecordingsFolder(context);

                for (File file : recordingsFolder.listFiles()) {
                    file.delete();
                }

                if (getNumberOfRecordings(context) == 0) {
                    String messageToDisplay = "All recordings on the phone have been deleted.";
                    MessageHelper.broadcastMessage(messageToDisplay, SUCCESSFULLY_DELETED_RECORDINGS,
                            MANAGE_RECORDINGS_ACTION, context);

                    // Delete any recording notes files
                    File recordingNotesFolder = Util.getRecordingNotesFolder(context);

                    for (File file : recordingNotesFolder.listFiles()) {
                        file.delete();
                    }

                    Prefs prefs = new Prefs(context);
                    prefs.setLatestBirdCountRecordingFileNameNoExtension(null);

                } else {
                    String messageToDisplay = "There was a problem. The recordings were NOT deleted.";
                    MessageHelper.broadcastMessage(messageToDisplay, FAILED_RECORDINGS_NOT_DELETED,
                            MANAGE_RECORDINGS_ACTION, context);
                }
            } catch (Exception ex) {
                Log.e(TAG, ex.getLocalizedMessage(), ex);
            }
        }).start();
    }

    public static int getNumberOfRecordings(Context context) {
        File recordingsFolder = Util.getRecordingsFolder(context);
        File[] recordingFiles = recordingsFolder.listFiles();
        return recordingFiles.length;
    }

    // https://stackoverflow.com/questions/1819142/how-should-i-validate-an-e-mail-address
    public static boolean isValidEmail(CharSequence target) {
        return !TextUtils.isEmpty(target) && android.util.Patterns.EMAIL_ADDRESS.matcher(target).matches();
    }

    public static void setGroups(Context context, ArrayList<String> groupsArrayList) {
        try {
            JSONArray groupsArrayJSON = new JSONArray();
            for (String group : groupsArrayList) {
                groupsArrayJSON.put(group);
            }

            JSONObject jsonGroups = new JSONObject();
            jsonGroups.put("groups", groupsArrayJSON);

            String groupsAsJsonString = jsonGroups.toString();
            Prefs prefs = new Prefs(context);
            prefs.setGroups(groupsAsJsonString);

        } catch (Exception ex) {
            Log.e(TAG, ex.getLocalizedMessage(), ex);
        }
    }

    public static void addGroup(Context context, String groupName) {
        ArrayList<String> localGroups = getGroupsStoredOnPhone(context);
        if (!localGroups.contains(groupName)) {
            localGroups.add(groupName);
        }
        setGroups(context, localGroups);
    }

    public static ArrayList<String> getGroupsStoredOnPhone(Context context) {
        Prefs prefs = new Prefs(context);
        ArrayList<String> groups = new ArrayList<>();
        String groupsString = prefs.getGroups();
        if (groupsString != null) {
            try {
                JSONObject jsonGroups = new JSONObject(groupsString);
                JSONArray groupsArrayJSON = jsonGroups.getJSONArray("groups");
                if (groupsArrayJSON != null) {
                    for (int i = 0; i < groupsArrayJSON.length(); i++) {
                        groups.add(groupsArrayJSON.getString(i));
                    }
                }

            } catch (JSONException e) {
                e.printStackTrace();
            }
        }

        return groups;
    }

    public static void getGroupsFromServer(final Context context) {
        new Thread(() -> {
            try {
                ArrayList<String> groupsFromServer = Server.getGroups(context);
                setGroups(context, groupsFromServer);
            } catch (Exception ex) {
                Log.e(TAG, ex.getLocalizedMessage(), ex);
            }
        }).start();
    }

    public static void addGroupToServer(final Context context, final String groupName,
                                        final Runnable onSuccess) {
        new Thread(() -> {
            try {
                if (Server.addGroupToServer(context, groupName)) {
                    onSuccess.run();
                }
            } catch (Exception ex) {
                Log.e(TAG, ex.getLocalizedMessage(), ex);
            }
        }).start();
    }

    public static void setUseTestServer(final Context context, boolean useTestServer) {
        Prefs prefs = new Prefs(context);
        prefs.setUseTestServer(useTestServer);
        // Need to un register phone and remove groups, account
        unregisterPhone(context);
        signOutUser(context);
        prefs.setGroups(null);
    }

    public static void unregisterPhone(final Context context) {
        try {
            Prefs prefs = new Prefs(context);

            prefs.setGroupName(null);
            prefs.setDevicePassword(null);
            prefs.setDeviceName(null);
            prefs.setDeviceToken(null);
            FirebaseCrashlytics.getInstance().setUserId(String.format("%s-%s-%d", null, null, 0));

        } catch (Exception ex) {
            Log.e(TAG, "Error Un-registering device.");
        }

    }

    public static void signOutUser(final Context context) {
        try {
            Prefs prefs = new Prefs(context);
            prefs.setUserSignedIn(false);
        } catch (Exception ex) {
            Log.e(TAG, "Error Un-registering user.");
        }
    }

    public static boolean isPhoneRegistered(final Context context) {
        Prefs prefs = new Prefs(context);
        String groupNameFromPrefs = prefs.getGroupName();
        String deviceNameFromPrefs = prefs.getDeviceName();
        return groupNameFromPrefs != null && deviceNameFromPrefs != null;
    }

    public static boolean haveAllPermissions(Context context, String[] permissions) {

        // String permissions[] = {Manifest.permission.WRITE_EXTERNAL_STORAGE,
        // Manifest.permission.RECORD_AUDIO, Manifest.permission.ACCESS_FINE_LOCATION}

        for (String permission : permissions) {
            if (ContextCompat.checkSelfPermission(context,
                    permission) != PackageManager.PERMISSION_GRANTED) {

                return false;

            }
        }

        return true;
    }

    public static boolean wasGrantedPermission(int[] grantResults) {
        return grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED;
    }

    public static boolean isBirdCountRecording(String type) {
        return type.equalsIgnoreCase(Prefs.BIRD_COUNT_5_ALARM) || type.equalsIgnoreCase(Prefs.BIRD_COUNT_10_ALARM)
                || type.equalsIgnoreCase(Prefs.BIRD_COUNT_15_ALARM);
    }

    public static boolean isUIRecording(String type) {
        return type.equalsIgnoreCase(Prefs.RECORD_NOW_ALARM) || isBirdCountRecording(type);
    }

    public static long getRecordingDuration(Context context, String typeOfRecording, String offsetType) {
        Prefs prefs = new Prefs(context);
        long recordTimeSeconds = (long) prefs.getRecordingDuration();

        if (typeOfRecording.equalsIgnoreCase(Prefs.BIRD_COUNT_5_ALARM)) {
            recordTimeSeconds = 60 * 5;
        } else if (typeOfRecording.equalsIgnoreCase(Prefs.BIRD_COUNT_10_ALARM)) {
            recordTimeSeconds = 60 * 10;
        } else if (typeOfRecording.equalsIgnoreCase(Prefs.BIRD_COUNT_15_ALARM)) {
            recordTimeSeconds = 60 * 15;
        } else if (typeOfRecording.equalsIgnoreCase(Prefs.REPEATING_ALARM) && prefs.getUseSunAlarms()
                && !offsetType.equals(Prefs.NORMAL_URI)) {
            recordTimeSeconds = prefs.getRecLength() * 60;
        }

        if (prefs.getUseShortRecordings()) { // for testing
            recordTimeSeconds = 1;

            if (typeOfRecording.equalsIgnoreCase(Prefs.BIRD_COUNT_5_ALARM)) {
                recordTimeSeconds = recordTimeSeconds * 5;
            } else if (typeOfRecording.equalsIgnoreCase(Prefs.BIRD_COUNT_10_ALARM)) {
                recordTimeSeconds = recordTimeSeconds * 10;
            } else if (typeOfRecording.equalsIgnoreCase(Prefs.BIRD_COUNT_15_ALARM)) {
                recordTimeSeconds = recordTimeSeconds * 15;
            } else if (typeOfRecording.equalsIgnoreCase(Prefs.REPEATING_ALARM) && prefs.getUseSunAlarms()
                    && !offsetType.equals(Prefs.NORMAL_URI)) {
                recordTimeSeconds = prefs.getRecLength();
            }
        }

        if (typeOfRecording.equalsIgnoreCase(Prefs.RECORD_NOW_ALARM)) {
            recordTimeSeconds += 1; // help to recognise recordNowButton recordings
        }
        Log.d(TAG, "recording duration of " + typeOfRecording + "  is" + recordTimeSeconds);
        return recordTimeSeconds;
    }

    public static void saveRecordingNote(Context context, String latestRecordingFileName, String weatherNote,
                                         String countedByNote, String otherNote) {
        File file = new File(Util.getRecordingNotesFolder(context), latestRecordingFileName + ".json");

        JSONObject recordingNotes = new JSONObject();
        try {
            recordingNotes.put("Weather", weatherNote);
            recordingNotes.put("Counted By", countedByNote);
            recordingNotes.put("Other", otherNote);

            Writer output = new BufferedWriter(new FileWriter(file));
            output.write(recordingNotes.toString());
            output.close();

        } catch (Exception ex) {
            Log.e(TAG, "exception", ex);
        }
    }

    public static String getRecordingFileExtension() {
        return RECORDING_FILE_EXTENSION;
    }

    public static File getNotesFileForLatestRecording(Context context) {
        Prefs prefs = new Prefs(context);
        String latestRecordingFileNameWithOutExtension = prefs.getLatestBirdCountRecordingFileNameNoExtension();
        if (latestRecordingFileNameWithOutExtension == null) {
            return null;
        } else {
            String notesFilePathName = getRecordingNotesFolder(context) + "/" + latestRecordingFileNameWithOutExtension
                    + ".json";
            return new File(notesFilePathName);
        }
    }

    public static JSONObject getNotesFromNoteFile(File notesFile) {
        if (!notesFile.exists()) {
            return null;
        }
        StringBuilder jsonText = new StringBuilder();
        JSONObject jsonNotes = null;

        try {
            BufferedReader br = new BufferedReader(new FileReader(notesFile));
            String line;

            while ((line = br.readLine()) != null) {
                jsonText.append(line);
                jsonText.append('\n');
            }
            br.close();

            jsonNotes = new JSONObject(jsonText.toString());
        } catch (Exception ex) {
            Log.e(TAG, ex.getLocalizedMessage());
        }
        return jsonNotes;
    }

    public static boolean hasSuperUserAccess() {
        return ExecuteAsRootBase.canRunRootCommands();
    }

    public static void requestSuperUser() {
        try {
            Runtime.getRuntime().exec("su");
        } catch (IOException ex) {
            Log.e(TAG, ex.getLocalizedMessage(), ex);
        }
    }

    public static void changeAlarmType(Context context) {
        AlarmManager alarmManager = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
        Intent myIntent = getRepeatingAlarmIntent(context, Prefs.NOON_OFFSET);
        PendingIntent pendingIntent = PendingIntent.getBroadcast(context, 0, myIntent, PendingIntent.FLAG_NO_CREATE);
        if (pendingIntent != null) {
            pendingIntent.cancel();
            alarmManager.cancel(pendingIntent);
        }
        createTheNextSingleStandardAlarm(context, null, Prefs.REPEATING_ALARM);
    }

    public static class Alarm {
        public long TimeMillis;
        public String OffsetType;

        public Alarm(long timeMS, String offset) {
            this.TimeMillis = timeMS;
            this.OffsetType = offset;
        }
    }

}
