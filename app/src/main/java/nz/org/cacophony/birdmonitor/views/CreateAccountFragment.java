package nz.org.cacophony.birdmonitor.views;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.text.method.LinkMovementMethod;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.TextView;

import androidx.fragment.app.Fragment;

import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;

import org.json.JSONObject;

import nz.org.cacophony.birdmonitor.MessageHelper;
import nz.org.cacophony.birdmonitor.MessageHelper.Action;
import nz.org.cacophony.birdmonitor.Prefs;
import nz.org.cacophony.birdmonitor.R;
import nz.org.cacophony.birdmonitor.Server;
import nz.org.cacophony.birdmonitor.Util;

public class CreateAccountFragment extends Fragment {

    public static final Action SERVER_SIGNUP_ACTION = new Action("SERVER_SIGNUP");
    private static final String TAG = "CreateAccountFragment";
    private TextView tvTitle;
    private TextInputLayout tilUsername;
    private TextInputEditText etUsername;
    private TextInputLayout tilEmail;
    private TextInputEditText etEmail;
    private TextInputLayout tilPassword1;
    private TextInputEditText etPassword1;
    private TextInputLayout tilPassword2;
    private TextInputEditText etPassword2;
    private Button btnSignUp;
    private TextView tvMessages;
    private CheckBox cbEndUserAgreement;
    private TextView tvEndUserAgreement;
    private TextView tvPrivacyPolicy;

    private final BroadcastReceiver messageHandler = MessageHelper.createReceiver(this::onMessage);

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        View view = inflater.inflate(R.layout.fragment_create_account, container, false);

        tvTitle = view.findViewById(R.id.tvTitle);
        tilUsername = view.findViewById(R.id.tilUsername);
        etUsername = view.findViewById(R.id.etUsername);
        tilEmail = view.findViewById(R.id.tilEmail);
        etEmail = view.findViewById(R.id.etEmail);
        tilPassword1 = view.findViewById(R.id.tilPassword1);
        etPassword1 = view.findViewById(R.id.etPassword1);
        tilPassword2 = view.findViewById(R.id.tilPassword2);
        etPassword2 = view.findViewById(R.id.etPassword2);
        btnSignUp = view.findViewById(R.id.btnSignUp);
        //  btnForgetUser = (Button) view.findViewById(R.id.btnSignOutUser);
        tvMessages = view.findViewById(R.id.tvMessagesCreateAccount);
        cbEndUserAgreement = view.findViewById(R.id.cbEndUserAgreement);
        tvEndUserAgreement = view.findViewById(R.id.tvEndUserAgreement);
        tvPrivacyPolicy = view.findViewById(R.id.tvPrivacyPolicy);

        tvPrivacyPolicy.setMovementMethod(LinkMovementMethod.getInstance());
        tvPrivacyPolicy.setOnClickListener(v -> {
            Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://cacophony.org.nz/app-privacy"));
            startActivity(browserIntent);
        });

        setUserVisibleHint(false);

        btnSignUp.setOnClickListener(v -> createUserButtonPressed());

        return view;
    }

    @SuppressWarnings("EmptyMethod")
    @Override
    public void onResume() {
        super.onResume();

    }

    @Override
    public void setUserVisibleHint(final boolean visible) {
        super.setUserVisibleHint(visible);
        if (getActivity() == null) {
            return;
        }
        if (visible) {
            MessageHelper.registerMessageHandler(SERVER_SIGNUP_ACTION, messageHandler, getActivity());
            displayOrHideGUIObjects();

        } else {
            MessageHelper.unregisterMessageHandler(messageHandler, getActivity());
        }
    }

    private void displayOrHideGUIObjects() {

        tvTitle.setVisibility(View.VISIBLE);
        tilUsername.setVisibility(View.VISIBLE);
        tilEmail.setVisibility(View.VISIBLE);
        tilPassword1.setVisibility(View.VISIBLE);
        tilPassword2.setVisibility(View.VISIBLE);

        btnSignUp.setVisibility(View.VISIBLE);
        tvMessages.setText("");
    }

    private void createUserButtonPressed() {

        Prefs prefs = new Prefs(getActivity().getApplicationContext());

        if (prefs.getInternetConnectionMode().equalsIgnoreCase("offline")) {
            ((SetupWizardActivity) getActivity()).displayOKDialogMessage("Oops", "The internet connection (in Advanced) has been set 'offline' - so this device can not be registered");
            return;
        }

        if (!Util.isNetworkConnected(getActivity().getApplicationContext())) {
            ((SetupWizardActivity) getActivity()).displayOKDialogMessage("Oops", "The phone is not currently connected to the internet - please fix and try again\"");
            return;
        }

        if (!cbEndUserAgreement.isChecked()) {
           ((SetupWizardActivity) getActivity()).displayOKDialogMessage("Terms & Conditions", "You must accept the end user agreement terms to create an account.");
            return;
        }

        // Check that the username is valid, at least 5 characters.
        String username = etUsername.getText().toString();
        if (username.length() < 1) {
            ((SetupWizardActivity) getActivity()).displayOKDialogMessage("Oops", "Please enter a Username of at least 5 characters (no spaces)");
            return;
        } else if (username.length() < 5) {
            ((SetupWizardActivity) getActivity()).displayOKDialogMessage("Oops", username + " is not a valid username. Please use at least 5 characters (no spaces)");
            return;
        }

        //Check email is valid
        String emailAddress = etEmail.getText().toString();

        if (emailAddress.length() < 1) {
            ((SetupWizardActivity) getActivity()).displayOKDialogMessage("Oops", "Please enter an email address");
            return;
        } else if (!Util.isValidEmail(emailAddress)) {
            ((SetupWizardActivity) getActivity()).displayOKDialogMessage("Oops", emailAddress + " is not a valid email address.");
            return;
        }

        //Check password is valid
        String etPassword1 = ((EditText) getView().findViewById(R.id.etPassword1)).getText().toString();
        if (etPassword1.length() < 8) {
            ((SetupWizardActivity) getActivity()).displayOKDialogMessage("Oops", "Minimum password length is 8 characters.");
            return;
        }
        String etPassword2 = ((EditText) getView().findViewById(R.id.etPassword2)).getText().toString();
        if (!etPassword1.equals(etPassword2)) {
            ((SetupWizardActivity) getActivity()).displayOKDialogMessage("Oops", "Passwords must match.");
            return;
        }

        tilUsername.setVisibility(View.GONE);
        tilEmail.setVisibility(View.GONE);
        tilPassword1.setVisibility(View.GONE);
        tilPassword2.setVisibility(View.GONE);

        tvMessages.setText(getString(R.string.attempting_to_creat));

        signUp(username, emailAddress, etPassword1, getActivity().getApplicationContext());
    }

    private void signUp(final String username, final String emailAddress, final String password, final Context context) {
        disableFlightMode();

        // Now wait for network connection as disableFlightMode takes a while
        if (!Util.waitForNetworkConnection(getActivity().getApplicationContext(), true)) {
            Log.e(TAG, "Failed to get internet connection");
            return;
        }

        new Thread(() -> Server.signUp(username, emailAddress, password, context)).start();
    }

    private void disableFlightMode() {
        try {
            Util.disableFlightMode(getActivity().getApplicationContext());
        } catch (Exception ex) {
            Log.e(TAG, ex.getLocalizedMessage(), ex);
            ((SetupWizardActivity) getActivity()).displayOKDialogMessage("Error", "Error disabling flight mode.");
        }
    }

    private void onMessage(Intent intent) {
        Prefs prefs = new Prefs(getActivity());
        try {
            if (getView() == null) {
                return;
            }
            String jsonStringMessage = intent.getStringExtra("jsonStringMessage");

            if (jsonStringMessage != null) {


                JSONObject joMessage = new JSONObject(jsonStringMessage);
                String messageType = joMessage.getString("messageType");
                String messageToDisplay = joMessage.getString("messageToDisplay");

                if (messageType.equalsIgnoreCase("SUCCESSFULLY_CREATED_USER")) {

                    Util.signOutUser(getActivity().getApplicationContext());
                    prefs.setUsername(etUsername.getText().toString());
                    prefs.setUserNameOrEmailAddress(etUsername.getText().toString());

                    tvTitle.setVisibility(View.GONE);

                    btnSignUp.setVisibility(View.GONE);

                    etUsername.setText("");
                    etEmail.setText("");
                    etPassword1.setText("");
                    etPassword2.setText("");

                    // tvMessages.setVisibility(View.VISIBLE); // not sure if setText will cause an error if it isn't visible?
                    tvMessages.setText(messageToDisplay + "\n\nSwipe to next screen to sign in.");

                } else {
                    tilUsername.setVisibility(View.VISIBLE);
                    tilEmail.setVisibility(View.VISIBLE);
                    tilPassword1.setVisibility(View.VISIBLE);
                    tilPassword2.setVisibility(View.VISIBLE);
                    tvMessages.setText("");
                    ((SetupWizardActivity) getActivity()).displayOKDialogMessage("Error", messageToDisplay);
                }

            }

        } catch (Exception ex) {

            Log.e(TAG, ex.getLocalizedMessage(), ex);

            tilUsername.setVisibility(View.VISIBLE);
            tilEmail.setVisibility(View.VISIBLE);
            tilPassword1.setVisibility(View.VISIBLE);
            tilPassword2.setVisibility(View.VISIBLE);
        }
    }

    public enum MessageType {
        SUCCESSFULLY_CREATED_USER,
        FAILED_TO_CREATE_USER
    }
}