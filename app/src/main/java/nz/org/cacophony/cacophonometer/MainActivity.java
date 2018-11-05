package nz.org.cacophony.cacophonometer;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;
import android.support.test.espresso.IdlingRegistry;
import android.support.v4.content.LocalBroadcastManager;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;


public class MainActivity extends AppCompatActivity implements IdlingResourceForEspressoTesting{
    // Register with idling counter
   // https://developer.android.com/training/testing/espresso/idling-resource.html
   // stackoverflow.com/questions/25470210/using-espresso-idling-resource-with-multiple-activities // this gave me idea to use an interface for app under test activities e.g MainActivity
    // https://www.youtube.com/watch?v=uCtzH0Rz5XU

    private static final String TAG = MainActivity.class.getName();
    private static final String intentAction = "nz.org.cacophony.cacophonometerlite.MainActivity";


    @Override
    protected void onStart() {
        super.onStart();
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(intentAction);
    }


    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main2);

        //https://developer.android.com/training/appbar/setting-up#java
        Toolbar myToolbar = (Toolbar) findViewById(R.id.my_toolbar);
        setSupportActionBar(myToolbar);

        // https://stackoverflow.com/questions/3488664/how-to-set-different-label-for-launcher-rather-than-activity-title
        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle(R.string.app_name);
        }

        Prefs prefs = new Prefs(this.getApplicationContext());
        prefs.setRecordingDurationSeconds();
        prefs.setNormalTimeBetweenRecordingsSeconds();
        prefs.setTimeBetweenFrequentRecordingsSeconds();
        prefs.setTimeBetweenVeryFrequentRecordingsSeconds();
        prefs.setTimeBetweenGPSLocationUpdatesSeconds();
        prefs.setDawnDuskOffsetMinutes();
        prefs.setDawnDuskIncrementMinutes();
        prefs.setLengthOfTwilightSeconds();
        prefs.setTimeBetweenUploadsSeconds();
        prefs.setTimeBetweenFrequentUploadsSeconds();
        prefs.setBatteryLevelCutoffRepeatingRecordings();
        prefs.setBatteryLevelCutoffDawnDuskRecordings();

        if (prefs.getIsFirstTime()) {
            prefs.setDateTimeLastRepeatingAlarmFiredToZero();
            prefs.setDateTimeLastUpload(0);
            prefs.setInternetConnectionMode("normal");
            prefs.setIsDisabled(false);
            prefs.setIsDisableDawnDuskRecordings(false);
            Util.displayHelp(this, "Introduction");

            prefs.setIsFirstTime();
        }

        // Now create the alarms that will cause the recordings to happen
        Util.createTheNextSingleStandardAlarm(getApplicationContext());
        DawnDuskAlarms.configureDawnAndDuskAlarms(getApplicationContext(), true);
        Util.createCreateAlarms(getApplicationContext());
        Util.setUpLocationUpdateAlarm(getApplicationContext());

    }

    @Override
    protected void onPause() {
        super.onPause();
        //https://stackoverflow.com/questions/8802157/how-to-use-localbroadcastmanager
        LocalBroadcastManager.getInstance(this).unregisterReceiver(onNotice);
    }

    @Override
    public void onResume() {
        super.onResume();
        Prefs prefs = new Prefs(this.getApplicationContext());

        if (prefs.getIsDisabled()){
            ((Button)findViewById(R.id.btnDisable)).setText("Enable Recording");
            ((Button)findViewById(R.id.btnDisable)).setBackgroundColor(getResources().getColor(R.color.colorAlert));
        }else{
            ((Button)findViewById(R.id.btnDisable)).setText("Disable Recording");
            ((Button)findViewById(R.id.btnDisable)).setBackgroundColor(getResources().getColor(R.color.accent));
        }
        // listens for events broadcast from ?
        IntentFilter iff = new IntentFilter("event");
        LocalBroadcastManager.getInstance(this).registerReceiver(onNotice, iff);
    }

    @Override
    protected void onStop() {
        super.onStop();
    }

    @Override
    protected void onRestart() {
        super.onRestart();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main_help, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case R.id.button_help:
                Util.displayHelp(this, "Introduction");
                return true;

            default:
                // If we got here, the user's action was not recognized.
                // Invoke the superclass to handle it.
                return super.onOptionsItemSelected(item);
        }
    }

    public void launchSetupActivity(@SuppressWarnings("UnusedParameters") View v) {

        try {
            Intent intent = new Intent(this, RegisterActivity.class);
            startActivity(intent);
        } catch (Exception ex) {
            Log.e(TAG, ex.getLocalizedMessage());
        }
    }



    public void launchWalkingActivity(@SuppressWarnings("UnusedParameters") View v) {
        try {
            Intent intent = new Intent(this, WalkingActivity.class);
            startActivity(intent);
        } catch (Exception ex) {
            Log.e(TAG, ex.getLocalizedMessage());
        }
    }

    public void launchVitalsActivity(@SuppressWarnings("UnusedParameters") View v) {
        try {
            Intent intent = new Intent(this, VitalsActivity.class);
            startActivity(intent);
        } catch (Exception ex) {
            Log.e(TAG, ex.getLocalizedMessage());
        }
    }

    public void launchAdvancedActivity(@SuppressWarnings("UnusedParameters") View v) {
        try {
            Intent intent = new Intent(this, InternetConnectionActivity.class);
            startActivity(intent);
        } catch (Exception ex) {
            Log.e(TAG, ex.getLocalizedMessage());
        }
    }

    public void launchDisableActivity(@SuppressWarnings("UnusedParameters") View v) {
        try {
            Intent intent = new Intent(this, DisableActivity.class);
            startActivity(intent);
        } catch (Exception ex) {
            Log.e(TAG, ex.getLocalizedMessage());
        }
    }




    private final BroadcastReceiver onNotice = new BroadcastReceiver() {
        //https://stackoverflow.com/questions/8802157/how-to-use-localbroadcastmanager

        // broadcast notification coming from ??
        @Override
        public void onReceive(Context context, Intent intent) {
            try {
                String message = intent.getStringExtra("message");
                if (message != null) {


                }

            } catch (Exception ex) {

                Log.e(TAG, ex.getLocalizedMessage());
            }
        }
    };
    /**
     * Only used by testing code
     */
    public void registerEspressoIdlingResources() {
        // https://developer.android.com/reference/android/support/test/espresso/IdlingRegistry
        //https://www.programcreek.com/java-api-examples/index.php?api=android.support.test.espresso.IdlingRegistry
        IdlingRegistry.getInstance().register(registerIdlingResource);
        IdlingRegistry.getInstance().register(recordNowIdlingResource);
        IdlingRegistry.getInstance().register(uploadingIdlingResource);
        IdlingRegistry.getInstance().register(toggleAirplaneModeIdlingResource);
    }
    /**
     * Only used by testing code
     */
    public void unRegisterEspressoIdlingResources() {
        IdlingRegistry.getInstance().unregister(registerIdlingResource);
        IdlingRegistry.getInstance().unregister(recordNowIdlingResource);
        IdlingRegistry.getInstance().unregister(uploadingIdlingResource);
        IdlingRegistry.getInstance().unregister(toggleAirplaneModeIdlingResource);

//        if (toggleAirplaneModeIdlingResource != null) {
//            IdlingRegistry.getInstance().unregister(toggleAirplaneModeIdlingResource);
//        }
    }

}
