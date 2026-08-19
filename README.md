# Digital Signature (.NET 8)

A simple, modular, and secure digital signature solution in .NET 8 implementing PKCS#7 / CMS detached signatures and database public key verification.

---

## Projects

- **`Sign.PDF/`**: PDF digital signature engine (ISO 32000 compliant using PDFsharp).
- **`Sign.Tests/`**: Automated xUnit test suite for digital signing and security verification.

---

## Security Model

```text
[CLIENT (User Machine)]                                   [SERVER + DATABASE]
         |                                                         |
(Holds 'user_key.pfx')                                    (Stores 'dbPublicKey' in DB)
         |                                                         |
 (1) Signs PDF with Private Key                                    |
         |                                                         |
         | ---- (2) Sends signed PDF to Server ------------------> |
         |                                                         |
         |                                                 (3) Checks integrity (hash)
         |                                                 (4) Extracts public key from PDF
         |                                                 (5) Matches with Database Key
         |                                                         |
         | <--- (6) "Signature VALID & Matches User Record" -------|
```

1. **Private Keys:** Stored securely on the client machine in password-protected `.pfx` files or Base64 PFX strings.
2. **Public Keys:** Stored in the server database to verify signer identity and prevent forgery.

---

## Quick Start

### Prerequisites
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

### 1. Run App Demo
```bash
dotnet run --project Sign.PDF/Sign.PDF.csproj
```

### 2. Run Unit Tests
```bash
dotnet test
```

---

## Test Specifications

| Test Case ID | Test Function Name | Description | Expected Result |
| :---: | :--- | :--- | :--- |
| **`TC-PDF-01`** | `TC_PDF_01_GenerateCertificate_ShouldReturnPfxBytesAndPublicKey` | Generate certificate and return PFX byte array and public key. | Returns `pfxBytes` opening with password and valid DB public key. |
| **`TC-PDF-02`** | `TC_PDF_02_SignAndVerify_WithMatchingDatabasePublicKey_ShouldSucceed` | Legitimate user signs PDF and server verifies with DB public key. | Returns `true` (signature valid and matches DB record). |
| **`TC-PDF-03`** | `TC_PDF_03_Verify_WithUnauthorizedAttackerKey_ShouldFail` | Attacker signs PDF with an unauthorized keypair. | Returns `false` (key does not match database record). |
| **`TC-PDF-04`** | `TC_PDF_04_Verify_WhenSignedDocumentIsTampered_ShouldFail` | Signed PDF content is modified after signing. | Returns `false` (cryptographic hash mismatch). |
| **`TC-PDF-05`** | `TC_PDF_05_Verify_WhenDocumentHasNoSignature_ShouldFail` | Verify an unsigned PDF document. | Returns `false` (missing signature dictionaries). |
| **`TC-PDF-06`** | `TC_PDF_06_SignAndVerify_WithPfxBytes_ShouldSucceed` | Legitimate user signs PDF directly with raw `byte[]` PFX key. | Returns `true` (signature valid and matches DB record). |
| **`TC-PDF-07`** | `TC_PDF_07_SignAndVerify_WithCustomFontPath_ShouldSucceed` | Sign PDF by providing a custom font file path. | Returns `true` (custom font loaded and PDF signature verified). |
| **`TC-PDF-08`** | `TC_PDF_08_SignAndVerify_InMemoryBytes_ShouldSucceed` | Sign and verify PDF purely in RAM using `byte[]` arrays without disk I/O. | Returns `true` (in-memory bytes signed and verified against DB key). |
| **`TC-PDF-09`** | `TC_PDF_09_GenerateCertificate_WithSupportedKeySizes_ShouldSucceed` | Generate certificate with 1024, 2048, 3072, and 4096-bit RSA keys. | Returns `true` (valid signatures across all 4 key sizes). |
| **`TC-PDF-10`** | `TC_PDF_10_GenerateCertificate_WithInvalidKeySize_ShouldThrowArgumentException` | Attempt to generate certificate with unsupported key sizes (e.g. 512, 1234). | Throws `ArgumentException`. |
| **`TC-PDF-11`** | `TC_PDF_11_GenerateCertificate_WithFullX500DistinguishedName_ShouldSucceed` | Generate certificate with full enterprise X.500 Subject DN (e.g. `CN=..., OU=..., O=..., C=VN`). | Returns `true` (signed and verified against DB key). |
| **`TC-PDF-12`** | `TC_PDF_12_GenerateCertificate_WithCustomValidityDays_ShouldSucceed` | Generate certificate with custom validity periods (e.g. 30, 365, 730 days). | Returns `true` (NotAfter expiration date matches UTC offset). |
| **`TC-PDF-13`** | `TC_PDF_13_GenerateCertificate_WithInvalidValidityDays_ShouldThrowArgumentException` | Attempt to generate certificate with non-positive validity days (e.g. 0, -10). | Throws `ArgumentException`. |
| **`TC-PDF-14`** | `TC_PDF_14_Sign_WithCustomPageIndexAndCoordinates_ShouldSucceed` | Sign on a custom page index (e.g. page 0) and custom rectangle coordinates. | Returns `true` (valid signature placed on custom page and position). |
| **`TC-PDF-15`** | `TC_PDF_15_Sign_WithInvalidPageIndex_ShouldThrowArgumentOutOfRangeException` | Attempt to sign on an out-of-range page index (e.g. -1 or 999). | Throws `ArgumentOutOfRangeException`. |
| **`TC-PDF-16`** | `TC_PDF_16_CoSigning_WithMultipleSignersInSingleCmsContainer_BothSignaturesShouldVerifySuccessfully` | Co-sign a PDF with multiple signers in a single CMS container (RFC 5652). | Returns `true` for all legitimate co-signers and `false` for unauthorized keys. |
| **`TC-PDF-17`** | `TC_PDF_17_SetFont_WithValidFontPath_ShouldSucceed` | Register a valid custom TrueType font file path. | Executes without exception. |
| **`TC-PDF-18`** | `TC_PDF_18_SetFont_WithNonExistentFontPath_ShouldThrowFileNotFoundException` | Attempt to register a non-existent font file path. | Throws `FileNotFoundException`. |
| **`TC-PDF-19`** | `TC_PDF_19_SetFont_WithNullOrWhitespaceFontPath_ShouldThrowFileNotFoundException` | Attempt to register null or empty/whitespace font path. | Throws `FileNotFoundException`. |
| **`TC-PDF-20`** | `TC_PDF_20_GenerateCertificate_WithUnicodeVietnameseSubject_ShouldSucceed` | Generate certificate with Vietnamese Unicode accents in name. | Returns `true` (signed and verified successfully). |
| **`TC-PDF-21`** | `TC_PDF_21_GenerateCertificate_WithSpecialCharactersInPassword_ShouldSucceed` | Generate and unlock PFX using complex special-character passwords. | Returns `true` (signed and verified successfully). |
| **`TC-PDF-22`** | `TC_PDF_22_GenerateCertificate_KeyUsageFlags_ShouldContainDigitalSignature` | Verify generated certificate X.509 Key Usage extensions. | Contains `X509KeyUsageFlags.DigitalSignature`. |
| **`TC-PDF-23`** | `TC_PDF_23_Sign_WithWrongPfxPassword_ShouldThrowException` | Attempt to sign PDF with incorrect PFX password. | Throws `CryptographicException` / `Exception`. |
| **`TC-PDF-24`** | `TC_PDF_24_Sign_WithCorruptedPfxBytes_ShouldThrowException` | Attempt to sign PDF with corrupted / invalid PFX byte array. | Throws `CryptographicException` / `Exception`. |
| **`TC-PDF-25`** | `TC_PDF_25_Sign_WithCorruptedInputPdfBytes_ShouldThrowException` | Attempt to sign corrupted non-PDF byte array. | Throws `Exception`. |
| **`TC-PDF-26`** | `TC_PDF_26_Sign_WithNonExistentCustomFontPath_ShouldThrowFileNotFoundException` | Pass non-existent font path to `Sign(..., customFontPath)`. | Throws `FileNotFoundException`. |
| **`TC-PDF-27`** | `TC_PDF_27_Sign_WithVietnameseUnicodeReasonAndLocation_ShouldSucceed` | Sign PDF with Vietnamese Unicode reason and location text. | Returns `true` (signature verified successfully). |
| **`TC-PDF-28`** | `TC_PDF_28_Sign_OnMultiPagePdf_WithSpecificPageIndices_ShouldSucceed` | Sign on an intermediate page (e.g. Page 1 of 3) in a multi-page PDF. | Returns `true` (signature verified successfully). |
| **`TC-PDF-29`** | `TC_PDF_29_Verify_WithEmptyOrCorruptedSignedPdfBytes_ShouldReturnFalse` | Verify empty or corrupted byte arrays as signed PDF. | Returns `false`. |
| **`TC-PDF-30`** | `TC_PDF_30_Verify_WithEmptyOrMismatchedPublicKeyBytes_ShouldReturnFalse` | Verify signed PDF with empty or mismatched public key. | Returns `false`. |
| **`TC-PDF-31`** | `TC_PDF_31_Verify_WhenSignatureContentsBlockIsTampered_ShouldReturnFalse` | Tamper with the cryptographic hex signature in `/Contents`. | Returns `false`. |
| **`TC-PDF-32`** | `TC_PDF_32_Verify_WithNonPdfGarbageBytes_ShouldReturnFalse` | Verify arbitrary plain text or binary garbage against public key. | Returns `false`. |
| **`TC-PDF-33`** | `TC_PDF_33_Verify_ConcurrentMultiThreaded_ShouldAllSucceed` | Concurrently verify a signed PDF across 30 simultaneous worker threads. | Returns `true` across all 30 parallel threads. |
| **`TC-PDF-34`** | `TC_PDF_34_Verify_BatchMultiplePublicKeys_ShouldCorrectlyIdentifyMatchingKey` | Batch test a signed PDF against 1 legitimate key and 4 impostor public keys. | Returns `true` only for the matching key and `false` for all 4 impostors. |
| **`TC-PDF-35`** | `TC_PDF_35_SignDataAndVerifyData_SequentialWorkflow_BothSignersShouldVerifySuccessfully` | Sequential detached digital signatures (`SignData` & `VerifyData`) across separate signers and timestamps. | Returns `true` for all legitimate detached signers, `false` for attackers and tampered documents. |

---

## ASP.NET Core Web API Integration Guide

`PdfSigner` is built as a **pure in-memory (`byte[]`) library** with zero disk I/O side effects, making it plug-and-play for **ASP.NET Core Web API**, microservices, and Docker containers.

### 1. Install Required NuGet Packages

Run in your ASP.NET Core API project directory:

```bash
dotnet add package PDFsharp --version 6.2.0-preview-1
dotnet add package System.Security.Cryptography.Pkcs --version 8.0.0
```

### 2. Configure TrueType Font in `.csproj`

Place your `Verdana.ttf` font inside a `Fonts/` folder in your Web API project, then ensure it is copied to the build output in your `.csproj`:

```xml
<ItemGroup>
  <None Update="Fonts\**\*">
    <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
  </None>
</ItemGroup>
```

### 3. Copy `PdfSigner.cs` & Create Controller

Copy [PdfSigner.cs](file:///Users/huynhbaquoc/Desktop/Project/digital%20signature/Digital-Signature/Sign.PDF/PdfSigner.cs) into your API's `Services/` or `Common/` folder. Then create your controller:

```csharp
using Microsoft.AspNetCore.Mvc;
using System.IO;

[ApiController]
[Route("api/[controller]")]
public class DigitalSignatureController : ControllerBase
{
    // POST /api/digitalsignature/generate-keypair
    [HttpPost("generate-keypair")]
    public IActionResult GenerateKeyPair([FromBody] GenerateKeyRequest request)
    {
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate(
            request.FullName, 
            request.Password, 
            keySizeInBits: 2048, 
            validityInDays: 365);

        // Store publicKeyBytes in your database for later verification:
        // await _userDb.SavePublicKeyAsync(request.UserId, publicKeyBytes);

        return Ok(new
        {
            Message = "Keypair generated successfully!",
            PublicKeyHex = Convert.ToHexString(publicKeyBytes),
            PfxBase64 = Convert.ToBase64String(pfxBytes)
        });
    }

    // POST /api/digitalsignature/sign-pdf
    [HttpPost("sign-pdf")]
    public async Task<IActionResult> SignPdf(
        [FromForm] IFormFile pdfFile,
        [FromForm] IFormFile pfxFile,
        [FromForm] string password,
        [FromForm] string reason = "Approved Contract",
        [FromForm] string location = "Ho Chi Minh City")
    {
        if (pdfFile == null || pfxFile == null)
        {
            return BadRequest("Both PDF document and PFX key file are required.");
        }

        // Read files into memory (byte[])
        using var pdfMs = new MemoryStream();
        await pdfFile.CopyToAsync(pdfMs);
        byte[] inputPdfBytes = pdfMs.ToArray();

        using var pfxMs = new MemoryStream();
        await pfxFile.CopyToAsync(pfxMs);
        byte[] pfxBytes = pfxMs.ToArray();

        // Sign PDF directly in RAM
        byte[] signedPdfBytes = PdfSigner.Sign(
            inputPdfBytes, 
            pfxBytes, 
            password, 
            reason: reason, 
            location: location);

        return File(signedPdfBytes, "application/pdf", $"signed_{pdfFile.FileName}");
    }

    // POST /api/digitalsignature/verify-pdf
    [HttpPost("verify-pdf")]
    public async Task<IActionResult> VerifyPdf(
        [FromForm] IFormFile signedPdfFile,
        [FromForm] string userId)
    {
        if (signedPdfFile == null)
        {
            return BadRequest("Signed PDF file is required.");
        }

        // 1. Fetch user's registered Public Key from Database
        // byte[] userPublicKey = await _userDb.GetPublicKeyAsync(userId);
        byte[] userPublicKey = ...;

        // 2. Read PDF bytes into memory
        using var ms = new MemoryStream();
        await signedPdfFile.CopyToAsync(ms);
        byte[] signedPdfBytes = ms.ToArray();

        // 3. Verify cryptographic integrity & match against database key
        bool isValid = PdfSigner.Verify(signedPdfBytes, userPublicKey);

        if (isValid == true)
        {
            return Ok(new { IsValid = true, Message = "Document is VALID and verified against Database." });
        }
        else
        {
            return BadRequest(new { IsValid = false, Message = "Verification FAILED: Document tampered or key mismatch." });
        }
    }
}

public class GenerateKeyRequest
{
    public string FullName { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}
```

