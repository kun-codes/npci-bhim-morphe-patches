package app.npci.bhim.patches

import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.patch.bytecodePatch
import app.template.patches.shared.Constants.COMPATIBILITY_BHIM

@Suppress("unused")
val bypassPairipProtection = bytecodePatch(
    name = "Bypass Pairip Protection",
    description = "Removes VMRunner.setContext, SignatureCheck.verifyIntegrity, and LicenseClient.checkLicense calls from Application.attachBaseContext to prevent pairip security initialization.",
    default = true,
) {
    compatibleWith(COMPATIBILITY_BHIM)

    dependsOn(bypassSignatureVerification)
    dependsOn(bypassLicenseCheck)

    execute {
        ApplicationAttachBaseContextFingerprint.method.addInstructions(
            0,
            """
                return-void
            """,
        )
    }
}
