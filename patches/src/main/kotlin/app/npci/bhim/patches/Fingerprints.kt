package app.npci.bhim.patches

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.InstructionLocation.MatchAfterImmediately
import app.morphe.patcher.methodCall
import app.morphe.patcher.opcode
import app.morphe.patcher.string
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode

/**
 * Fingerprint for com.pairip.SignatureCheck.verifyIntegrity(Context)
 * This method verifies APK signature and throws SignatureTamperedException if invalid.
 * Identified by the string "SHA-256" and the method signature check flow.
 */
object SignatureCheckFingerprint : Fingerprint(
    returnType = "V",
    parameters = listOf("Landroid/content/Context;"),
    filters = listOf(
        string("SHA-256"),
        string("Apk signature is invalid."),
    ),
    custom = { _, classDef ->
        classDef.type == "Lcom/pairip/SignatureCheck;"
    }
)

/**
 * Fingerprint for com.pairip.licensecheck.LicenseClient.checkLicense(Context)
 * This static method initiates the Play Store license verification.
 * Identified by the string "Skipping license check in isolated process."
 */
object LicenseCheckFingerprint : Fingerprint(
    returnType = "V",
    parameters = listOf("Landroid/content/Context;"),
    filters = listOf(
        string("Skipping license check in isolated process."),
    ),
    custom = { _, classDef ->
        classDef.type == "Lcom/pairip/licensecheck/LicenseClient;"
    }
)

/**
 * Fingerprint for com.pairip.application.Application.attachBaseContext(Context)
 * This is the entry point where all pairip security is initialized.
 * Identified by the sequence of calls: VMRunner.setContext -> SignatureCheck.verifyIntegrity -> LicenseClient.checkLicense
 */
object ApplicationAttachBaseContextFingerprint : Fingerprint(
    returnType = "V",
    parameters = listOf("Landroid/content/Context;"),
    filters = listOf(
        methodCall(
            definingClass = "Lcom/pairip/VMRunner;",
            name = "setContext",
        ),
        methodCall(
            definingClass = "Lcom/pairip/SignatureCheck;",
            name = "verifyIntegrity",
        ),
        methodCall(
            definingClass = "Lcom/pairip/licensecheck/LicenseClient;",
            name = "checkLicense",
        ),
    ),
    custom = { _, classDef ->
        classDef.type == "Lcom/pairip/application/Application;"
    }
)

/**
 * Fingerprint for Q4.Fi0zof57.sfPE() - Device details builder.
 * This method builds device details including rootStatus.
 * Identified by the string "safe" being set as rootStatus.
 */
object DeviceDetailsBuilderFingerprint : Fingerprint(
    returnType = "Lr3z/W6XuWJ;",
    filters = listOf(
        string("safe"),
    ),
    custom = { _, classDef ->
        classDef.type == "LQ4/Fi0zof57;"
    }
)

/**
 * Fingerprint for r3z.DEaXh.isEmpty() - Device integrity check.
 * This method checks if device recognition verdict fields are empty.
 * Identified by checking deviceIntegrity, basicIntegrity, strongIntegrity fields.
 */
object DeviceIntegrityCheckFingerprint : Fingerprint(
    returnType = "Z",
    parameters = emptyList(),
    custom = { methodDef, classDef ->
        classDef.type == "Lr3z/DEaXh;" && methodDef.name == "isEmpty"
    }
)

/**
 * Fingerprint for the root status comparison in Q4.JsDum.sfPE()
 * This static method compares root status from client vs server response.
 * Identified by the "safe" string comparison and getRootStatus calls.
 */
object RootStatusComparisonFingerprint : Fingerprint(
    returnType = "V",
    parameters = listOf("LQ4/JsDum;", "Lr3z/Uk0y;", "Lr3z/LIUfHTl5;"),
    filters = listOf(
        methodCall(
            name = "getRootStatus",
        ),
    ),
    custom = { _, classDef ->
        classDef.type == "LQ4/JsDum;"
    }
)
