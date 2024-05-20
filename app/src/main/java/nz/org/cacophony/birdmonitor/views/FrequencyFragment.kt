package nz.org.cacophony.birdmonitor.views

import nz.org.cacophony.birdmonitor.Util.setUseFrequentUploads
import android.widget.TextView
import android.view.LayoutInflater
import android.view.ViewGroup
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.CompoundButton
import android.widget.Switch
import androidx.core.widget.doAfterTextChanged
import androidx.core.widget.doOnTextChanged
import androidx.fragment.app.Fragment
import nz.org.cacophony.birdmonitor.Prefs
import nz.org.cacophony.birdmonitor.R
import nz.org.cacophony.birdmonitor.Util
import kotlin.random.Random
import kotlin.random.nextLong

class FrequencyFragment : Fragment() {
    private var swUseFrequentUploads: Switch? = null
    private var tvMessages: TextView? = null
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        // Inflate the layout for this fragment
        val view = inflater.inflate(R.layout.fragment_frequency, container, false)
        userVisibleHint = false
        tvMessages = view.findViewById(R.id.tvMessages)
        swUseFrequentUploads = view.findViewById(R.id.swUseFrequentUploads)
        displayOrHideGUIObjects()
        swUseFrequentUploads?.setOnCheckedChangeListener(CompoundButton.OnCheckedChangeListener { _: CompoundButton?, isChecked: Boolean ->
            setUseFrequentUploads(
                requireActivity().applicationContext, isChecked
            )
            displayOrHideGUIObjects()
        })
        val prefs = Prefs(requireActivity().applicationContext)
        val randomText = view.findViewById<TextView>(R.id.RandomSeedText)
        val randomButton = view.findViewById<Button>(R.id.RandomSeedButton)
        val randomSeed = prefs.randomSeed.toString()
        randomText.text = randomSeed
        // add a listener to the button
        randomButton.setOnClickListener {
            val newSeed = Random.nextLong(9999)
            randomText.text = newSeed.toString()
        }
        
        randomText.doAfterTextChanged { text ->
            if (text.isNullOrEmpty()) {
                return@doAfterTextChanged
            }
            val newSeed = text.toString().toLong()
            prefs.randomSeed = newSeed
            val alarm = Util.getNextAlarm(requireActivity().applicationContext, prefs, null)
            prefs.setTheNextSingleStandardAlarmUsingUnixTime(alarm.TimeMillis)
            Util.createTheNextSingleStandardAlarm(requireActivity().applicationContext, Prefs.RELATIVE, Prefs.INTENT_TYPE)
        }

        return view
    }

    @Deprecated("Deprecated in Java")
    override fun setUserVisibleHint(visible: Boolean) {
        super.setUserVisibleHint(visible)
        if (activity == null) {
            return
        }
        if (visible) {
            displayOrHideGUIObjects()
        }
    }

    fun displayOrHideGUIObjects() {
        val prefs = Prefs(activity)
        swUseFrequentUploads!!.isChecked = prefs.useFrequentUploads
        if (prefs.useFrequentUploads) {
            swUseFrequentUploads!!.text = "Upload after every recording is ON"
        } else {
            swUseFrequentUploads!!.text = "Upload after every recording is OFF"
        }
    }

    companion object {
        private const val TAG = "FrequencyFragment"
    }
}