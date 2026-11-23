package id.jayatech.rootdetector

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.display.DisplayManager
import android.os.Build
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import id.jayatech.rootdetector.rules.Rules

/**
 * Runtime device-safety protections for the *live* screen, complementing [RootDetector.scan]
 * (which reports what is installed/enabled). Use these on sensitive screens: login, PIN entry,
 * transfer confirmation, OTP display.
 *
 * - [protectFromOverlays] + [classifyTouch]: tapjacking / fake-overlay defence. Touches that
 *   arrive while another app's window covers ours are dropped and can be reported.
 * - [secureWindow]: FLAG_SECURE — blocks screenshots, screen recording, casting and the
 *   recents thumbnail for that window (the strongest mitigation for screen-share scams).
 * - [registerScreenCaptureListener]: API 34+ callback when the user takes a screenshot.
 *   Requires `<uses-permission android:name="android.permission.DETECT_SCREEN_CAPTURE"/>` in
 *   the host manifest (normal permission); without it this is a no-op returning null.
 * - [mirroringDisplays]: public presentation displays (Cast / Miracast / HDMI mirroring).
 *
 * Nothing here needs a dangerous permission and nothing throws into the host app.
 */
object DeviceSafetyGuard {

    enum class TouchObscured { NONE, PARTIAL, FULL }

    /**
     * Drop touches delivered while [view]'s window is obscured by another window
     * (View.filterTouchesWhenObscured). Apply to the confirm/PIN buttons or a whole screen root.
     */
    @JvmStatic
    fun protectFromOverlays(view: View) {
        view.filterTouchesWhenObscured = true
    }

    /**
     * Classify a touch: call from your own onTouch/dispatchTouchEvent to *report* (not only drop)
     * an overlay attack. PARTIAL is only reported on API 29+.
     */
    @JvmStatic
    fun classifyTouch(event: MotionEvent): TouchObscured =
        when (Rules.classifyTouchFlags(event.flags)) {
            Rules.ObscuredTouch.FULL -> TouchObscured.FULL
            Rules.ObscuredTouch.PARTIAL -> TouchObscured.PARTIAL
            Rules.ObscuredTouch.NONE -> TouchObscured.NONE
        }

    /**
     * FLAG_SECURE on the activity window: the content cannot be captured by screenshots,
     * screen recording, MediaProjection/remote-control apps or casting.
     */
    @JvmStatic
    fun secureWindow(activity: Activity, enabled: Boolean = true) {
        try {
            if (enabled) activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
            else activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } catch (_: Throwable) {
            // never crash the host app
        }
    }

    /** Handle returned by [registerScreenCaptureListener]; call [unregister] in onStop. */
    fun interface Registration {
        fun unregister()
    }

    /**
     * API 34+: [onCapture] runs (on the main thread) when the user screenshots this activity.
     * Register in onStart, unregister in onStop. Returns null below API 34 or when the host
     * manifest does not declare DETECT_SCREEN_CAPTURE.
     */
    @JvmStatic
    fun registerScreenCaptureListener(activity: Activity, onCapture: Runnable): Registration? {
        if (Build.VERSION.SDK_INT < 34) return null
        if (activity.checkSelfPermission("android.permission.DETECT_SCREEN_CAPTURE") !=
            PackageManager.PERMISSION_GRANTED
        ) return null
        return try {
            val callback = Activity.ScreenCaptureCallback { onCapture.run() }
            activity.registerScreenCaptureCallback(activity.mainExecutor, callback)
            Registration {
                try { activity.unregisterScreenCaptureCallback(callback) } catch (_: Throwable) {}
            }
        } catch (_: Throwable) {
            null
        }
    }

    /**
     * Names of displays the screen is currently being mirrored/cast to (empty if none).
     * Private virtual displays are ignored, so an app's own offscreen rendering does not count.
     */
    @JvmStatic
    fun mirroringDisplays(context: Context): List<String> = try {
        val dm = context.getSystemService(Context.DISPLAY_SERVICE) as? DisplayManager
        dm?.displays.orEmpty()
            .filter { Rules.isMirroringDisplay(it.displayId, it.flags) }
            .map { "#${it.displayId} ${it.name}" }
    } catch (_: Throwable) {
        emptyList()
    }
}
