package com.nationstrust.ntbdigital.ntb_digital

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import com.scottyab.rootbeer.RootBeer
import java.io.File


class RootUtil {
    fun isRooted(context: Context): Boolean {
        val rootBeerStatus = rootBeerStatus(context)
        val rootManagerAppStatus = hasRootManagerSystemApp(context)
        val suBinaryStatus = hasSuBinary()
        val emulatorStatus = isEmulator(context)
        val testKeysStatus = checkTestKeys()
        val permissionStatus = checkPermissions()
        val cyanogenStatus = checkCyanogenSettings(context)
        val superUserFileStatus = checkInstalledSuperUserFiles()
        val rootStatus = rootBeerStatus ||
                rootManagerAppStatus ||
                suBinaryStatus ||
                emulatorStatus ||
                testKeysStatus ||
                permissionStatus ||
                cyanogenStatus ||
                superUserFileStatus;
        return rootStatus
    }

    private fun rootBeerStatus(context: Context):Boolean {
        val rootBeer = RootBeer(context)
        return rootBeer.isRooted()
    }

    private fun hasRootManagerSystemApp(context: Context): Boolean {
        val blacklistedPackages = arrayOf(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.noshufou.android.su",
            "me.phh.superuser",
            "com.thirdparty.superuser",
            "com.zachspong.temprootremovejb",
            "com.ramdroid.appquarantine",
        )
        val rootOnlyApplications = arrayOf(
            "eu.chainfire.stickmount",
            "eu.chainfire.mobileodin.pro",
            "eu.chainfire.liveboot",
            "eu.chainfire.pryfi",
            "eu.chainfire.adbd",
            "eu.chainfire.recently",
            "eu.chainfire.flash",
            "eu.chainfire.stickmount.pro",
            "eu.chainfire.triangleaway",
            "org.adblockplus.android"
        )

        val pm = context.packageManager
        val installedPackages = pm.getInstalledPackages(0)

        var rootOnlyAppCount = 0

        for (packageInfo in installedPackages) {
            val packageName = packageInfo.packageName
            if (blacklistedPackages.contains(packageName)) {
                return true
            }
            if (rootOnlyApplications.contains(packageName)) {
                rootOnlyAppCount += 1
            }
        }
        return rootOnlyAppCount > 2
    }

    private fun hasSuBinary(): Boolean {
        return try {
            findBinary("su")
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    private fun findBinary(binaryName: String): Boolean {
        var found = false
        if (!found) {
            val places = arrayOf(
                "/sbin/",
                "/system/bin/",
                "/system/xbin/",
                "/data/local/xbin/",
                "/data/local/bin/",
                "/system/sd/xbin/",
                "/system/bin/failsafe/",
                "/data/local/",
                "/system/app/Superuser.apk",
                "/sbin/su",
                "/sbin/su/",
                "/system/bin/su",
                "/system/bin/su/",
                "/system/xbin/su",
                "/system/xbin/su/",
                "/data/local/xbin/su",
                "/data/local/bin/su",
                "/system/sd/xbin/su",
                "/system/bin/failsafe/su",
                "/data/local/su",
                "/su/bin/su",
                "/su/",
                "/data/local/xbin/",
                "/system/bin/.ext/",
                "/system/bin/failsafe/",
                "/system/sd/xbin/",
                "/su/xbin/",
                "/su/bin/",
                "/magisk/.core/bin/",
                "/system/usr/we-need-root/",
                "/system/xbin/",
                "/system/su",
                "/system/bin/.ext/.su",
                "/system/usr/we-need-root/su-backup",
                "/system/xbin/mu",
                "/system/su/",
                "/system/bin/.ext/.su/",
                "/system/usr/we-need-root/su-backup/",
                "/system/xbin/mu/",
                "/ipcData/local/",
                "/ipcData/local/xbin/",
            )
            for (where in places) {
                if (File(where + binaryName).exists()) {
                    found = true
                    break
                }
            }
        }
        return found
    }

    private fun isEmulator(context: Context): Boolean {
        val androidId = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
        val isEmulator = (Build.MANUFACTURER.contains("Genymotion")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.toLowerCase().contains("droid4x")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.HARDWARE.contains("goldfish")
                || Build.HARDWARE.contains("vbox86")
                || Build.HARDWARE.contains("ranchu")
                || Build.HARDWARE.toLowerCase().contains("nox")
                || Build.FINGERPRINT.startsWith("generic")
                || Build.PRODUCT.contains("sdk")
                || Build.PRODUCT == "google_sdk"
                || Build.PRODUCT == "sdk_x86"
                || Build.PRODUCT == "vbox86p"
                || Build.PRODUCT.toLowerCase().contains("nox")
                || Build.BOARD.toLowerCase().contains("nox")
                || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
                || androidId == null);
        return isEmulator
    }

    private fun checkTestKeys(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    private fun checkPermissions(): Boolean {
        val directoriesToCheck = arrayOf(
            "/data",
            "/",
            "/system",
            "/system/bin",
            "/system/sbin",
            "/system/xbin",
            "/vendor/bin",
            "/sys",
            "/sbin",
            "/etc",
            "/proc",
            "/dev"
        )
        for (dirName in directoriesToCheck) {
            val dir = File(dirName)
            if (dir.exists() && dir.canWrite() || dirName == "/data" && dir.canRead()) {
                return true
            }
        }
        return false
    }

    private fun checkCyanogenSettings(context: Context): Boolean {
        val settingPackageName = "com.android.settings"
        val cyanogenSuActivity = "cyanogenmod.Superuser"
        val pm = context.packageManager
        try {
            val settingsPackage =
                pm.getPackageInfo(settingPackageName, PackageManager.GET_ACTIVITIES)
            val settingsActivities = settingsPackage.activities
            for (activityInfo in settingsActivities) {
                val activityName = activityInfo.name
                if (activityName.equals(
                        "$settingPackageName.$cyanogenSuActivity",
                        ignoreCase = true
                    )
                ) {
                    return true
                }
            }
        } catch (e: PackageManager.NameNotFoundException) {
            e.printStackTrace()
        }
        return false
    }

    private fun checkInstalledSuperUserFiles(): Boolean {
        val superUserAPKPaths = arrayOf(
            "/system/app/Superuser.apk",
            "/system/app/superuser.apk",
            "/system/app/Superuser/Superuser.apk",
            "/system/app/Superuser/superuser.apk",
            "/system/app/superuser/Superuser.apk",
            "/system/app/superuser/superuser.apk",
        )
        for (path in superUserAPKPaths) {
            val suapk = File(path)
            if (suapk.exists()) {
                return true
            }
        }
        return false
    }
}