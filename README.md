# Aiia Payload Encryption Sample

Code sample demonstrating how to use the Payload Encryption functionality in the Aiia Enterprise product.
The Payload Encryption functionality is available in all of Aiia's products in the same way: 
 - The server's public key is exposed in the following endpoint `/v1/payload-encryption-key`
 - Services look at whether the `X-Payload-Encryption` header is present to enable the Payload Encryption feature

The official documentation can be found here:
https://docs.nordicapigateway.com/#/connecting-to-the-api/advanced-topics/?id=payload-encryption

## How to run
- Open the Solution in your favorite IDE
- Change the `clientId` and `clientSecret` variables to your sandbox credentials obtained in https://portal.aiia.eu/
- Run the Aiia.PayloadEncryption.Sample project with the `Aiia.PayloadEncryption.Sample` launch configuration
  - If you're running it on MacOS please see the Troubleshooting section below

## Troubleshooting
On MacOS you might run into trouble with using AES GCM encryption, e.g.
`Unhandled exception. System.PlatformNotSupportedException: Algorithm 'AesGcm' is not supported on this platform.`
It is not supported by default and requires the installation of openSSL.

In order to make it work you need to 
1. Install OpenSSL: `brew install openssl`
2. Modify the `launchSettings.json` to include the `"DYLD_LIBRARY_PATH"` variable to point to your local installation of the OpenSSL lib, e.g.

```
{
  "$schema": "http://json.schemastore.org/launchsettings.json",
  "profiles": {
    "Aiia.PayloadEncryption.Sample": {
      "commandName": "Project",
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development",
        "DYLD_LIBRARY_PATH": "/usr/local/opt/openssl@3/lib" // <= Path to your local installation of OpenSSL Lib
      }
    }
  }
}
```
