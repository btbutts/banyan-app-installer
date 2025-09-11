# Banyan App Installer

Automate installation of Banyan App on end-user devices.

See [Banyan documentation](https://docs.banyansecurity.io/docs/feature-guides/manage-users-and-devices/device-managers/distribute-desktopapp/) for more details.

---

## ⚠️ Attention

This repo contains a modified version of the Vanilla CSE (Cloud Secure Edge | formerly Banyan Security) Installation PowerShell script. Whilst the Vanilla version developed by SonicWall, Inc. is included directly below, the versions of the script within the _device_manager/windows_mod_ directory are intended for deployments where the endpoints are NOT directly joined to EntraID. This refers to Hybrid deployments, where endpoints are: <br>
<br>
**1.** On-Premise AD DS Joined + Intune Managed, OR<br>
**2.** On-Premise AD DS Joined & On-Premise Managed.

### Script Selection

* If your organization has a mix of Windows devices that are both directly EntraID joined, and On-Premise AD DS joined, use the script found in [_device_manager/windows_mod/EntraJoined_](device_manager/windows_mod/EntraJoined/)
* If your organziation's Windows endpoints are NOT at all directly joined to EntraID, use the script found in [_device_manager/windows_mod/noEntraJoined_](device_manager/windows_mod/noEntraJoined/)

<br>

### FAQ(s)

<details>
  <summary><strong>What's different between the modified Windows script(s) and the Vanilla script?</strong></summary>
<br>The original version of the CSE installation script for Windows devices was primarily intended for Intune managed endpoints that are also joined to EntraID. Whilst it is still possible to use that script for endpoints that are not joined to EntraID, as presently written, it will only work if you use the <strong>STAGED USER</strong>, alternative deployment scenario described in the <a href="https://docs.banyansecurity.io/docs/manage-users-and-devices/device-managers/distribute-desktopapp/#staged-user-and-zero-touch-installation" target="_blank" rel="noopener noreferrer">CSE Documentation</a>. This can lead to an undesriable behaviour for some organizations where each of their Windows endpoints known to CSE via the script device registration process are associated to a placeholder user in the CSE Command Center, shown as <em><strong>Staged User</strong></em>.

The modified version of the script remedies this by searching for the user's identity from other sources.<br><br>
</details>


<details>
  <summary><strong>How is the user's identity determined in the modified CSE installation script?</strong></summary>
<br>The modified scripts attempt to use a different registry key than is used in the vanilla version. The registry key should be available in any Windows machine that is joined to an on-premise AD DS deployment.

The script will both, fetch, and compare the identity retreived from the registry against the AD DS directory. In the event the identity matches, the determined identity, the user's UPN (User Principal Name) will be used to register the endpoint with CSE. For this to work correctly, the user's UPN and primary email address, IE: their _mail_ attribute, should have identical values. If the user's _UPN_ and _mail_ attribues have different values, the script can fallback to the UPN retreived from the registry. This occurance is seen in organizations where they have implemented a .local domain internally, but a .com, .net, .org, etc... domain externally.

**Note:** Since .local domains are invalid in most cloud IdPs (Identity Providers), such as EntraID, Okta, OneLogin, Duo, etc..., further modification of the script will be necessary to omit the _UPN_ and use the user's _mail_ attribute instead.<br><br>
</details>
<br>

### Other Important Information
#### Deployment Requirements
* The modified version of the script is not intended for kiosk machines, shared machines, or other machines that are used by multiple users. The modified script needs to reliably determine a single user from the registry. If multiple domain users have logged into the machine, any one of those user's identities may be used for the initial device registration process.
* It is important that the endpoint the script is ran on, have an active connection to the internal directory (On-Premise AD DS) deployment to successfully complete its validations and user attribute searches and mappings. Running the script without an active, working connection to the directory may lead to installation, or CSE device registration failure.
* For assistance configuring the various variables and script settings to directly configure the CSE application on Windows devices, consult the standard [CSE Documentation](https://docs.banyansecurity.io/docs/manage-users-and-devices/device-managers/distribute-desktopapp/) on this topic.
<br>

## Install using Zero Touch Flow

In the Banyan Command Center, navigate to **Settings** > **App Deployment**. Note down your org-specific app deployment parameters for use in the scripts below:
- Invite Code
- Deployment Key

The script will:
1. Create an `mdm-config.json` file that specifies app functionality
2. Download the *latest Banyan app* version and install it (you can also optionally specify an exact app version)
3. Stage the app with the device certificate
4. Start the app as the logged-on user


### MacOS

Launch a terminal and run:

```bash
sudo ./banyan-macos.sh <INVITE_CODE> <DEPLOYMENT_KEY> <APP_VERSION (optional)>
```

### Windows

Launch PowerShell as Administrator and run:

```powershell
.\banyan-windows.ps1 <INVITE_CODE> <DEPLOYMENT_KEY> <APP_VERSION (optional)>
```

### Linux

Launch a terminal and run:

```bash
sudo ./banyan-linux.sh <INVITE_CODE> <DEPLOYMENT_KEY> <APP_VERSION (optional)>
```
NOTE: The Linux script doesn't currently support MDM supplied user Information.

---

## Upgrade Flow

You can also use the scripts to upgrade the version of the Banyan app running on a device. Use the string `"upgrade"` for the Invite Code and Deployment Key parameters.

The script will:
1. Stop the app if it running
2. Download the *latest Banyan app* version and install it (you can also optionally specify an exact app version)
3. Start the app as the logged-on user


### MacOS

Launch a terminal and run:

```bash
sudo ./banyan-macos.sh upgrade upgrade <APP_VERSION (optional)>
```

### Windows

Launch PowerShell as Administrator and run:

```powershell
.\banyan-windows.ps1 upgrade upgrade <APP_VERSION (optional)>
```

### Linux

Launch a terminal and run:

```bash
sudo ./banyan-linux.sh upgrade <APP_VERSION (optional)>
```

---

## Notes for usage with Device Managers

We have pre-configured the main script to be run via Device Managers (such as VMware Workspace ONE, Jamf Pro, Kandji, Microsoft Intune, etc.).

### Jamf Pro

Use the [**banyan-macos-jamf.sh**](device_manager/banyan-macos-jamf.sh) script, following our [Jamf Pro - Zero Touch Installation doc](https://docs.banyansecurity.io/docs/feature-guides/manage-users-and-devices/device-managers/jamf-pro-zero-touch/).


### Kandji

Use the [**banyan-macos-kandji.sh**](device_manager/banyan-macos-kandji.sh) script, following our [Kandji- Zero Touch Installation doc](https://docs.banyansecurity.io/docs/feature-guides/manage-users-and-devices/device-managers/kandji-zero-touch/).


### Microsoft Intune

Use the [**banyan-windows-intune.ps1**](device_manager/banyan-windows-intune.ps1) script, following our [Intune - Zero Touch Installation doc](https://docs.banyansecurity.io/docs/feature-guides/manage-users-and-devices/device-managers/intune-zero-touch/).


### VMWare Workspace One UEM

Use our base scripts and customize as needed, following our [Workspace ONE UEM - Device Identity & Enhanced TrustScoring doc](https://docs.banyanops.com/docs/feature-guides/manage-users-and-devices/device-managers/workspace-one-cert-api/#wsone). You need to set a few additional parameters in the `mdm-config.json` file so Banyan’s TrustScoring engine can correlate data from devices running the Banyan Desktop App with the data in Workspace ONE UEM:

- `mdm_vendor_name` should be set to **Airwatch**
- `mdm_present` should be **true**
- `mdm_vendor_udid` should be the **DEVICE UDID**



