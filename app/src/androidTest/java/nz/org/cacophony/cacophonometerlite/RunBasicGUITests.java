package nz.org.cacophony.cacophonometerlite;



import org.junit.runner.RunWith;
import org.junit.runners.Suite;

// Runs all unit tests.
@RunWith(Suite.class)
@Suite.SuiteClasses({
        MainActivityGUIExists1.class,
        MainActivityPressRadioButtons.class,
        OffModeRadioButton.class

})
public class RunBasicGUITests {}


