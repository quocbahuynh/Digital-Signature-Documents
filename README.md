# Digital Signature (.NET 8)

A high-performance, modular, and secure digital signature solution in .NET 8 implementing PKCS#7 / CMS detached signatures (`SignData` & `VerifyData`), visual signature stamping (`StampVisualSignature`), and database public key verification.

---

## Projects

- **`Sign.PDF/`**: PDF visual stamping & digital signature engine.
- **`Sign.Tests/`**: Automated xUnit test suite covering 100% of cryptography, visual stamping, thread-safety, and security paths.

---

## Security Model (Detached Signatures + Visual Stamping)

```text
[CLIENT (User Machine)]                                   [SERVER + DATABASE]
         |                                                         |
(Holds 'user_key.pfx')                                    (Stores 'dbPublicKey' in DB)
         |                                                         |
 (1) Visual Stamp on PDF (StampVisualSignature)                    |
 (2) Signs PDF bytes with Private Key (SignData)                   |
         |                                                         |
         | ---- (3) Sends stamped PDF + Signature to Server -----> |
         |                                                         |
         |                                                 (4) Checks data integrity (hash)
         |                                                 (5) Extracts public key from signature
         |                                                 (6) Matches with Database Key (VerifyData)
         |                                                         |
         | <--- (7) "Signature VALID & Matches User Record" -------|
```

1. **Private Keys:** Stored securely on the client machine in password-protected `.pfx` byte arrays.
2. **Public Keys:** Stored in the server database to verify signer identity and prevent forgery.
3. **Visual Layer:** `StampVisualSignature` dynamically draws approval boxes anywhere on the PDF page.
4. **Crypto Layer:** `SignData` generates standard 1.1 KB PKCS#7 detached signatures for lightweight multi-signer database storage.

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
| **`TC-PDF-02`** | `TC_PDF_02_GenerateCertificate_WithAllowedKeySizes_ShouldSucceed` | Test RSA key sizes: 1024, 2048, 3072, and 4096 bits. | Returns valid certificates across all 4 key sizes. |
| **`TC-PDF-03`** | `TC_PDF_03_GenerateCertificate_WithInvalidKeySize_ShouldThrowArgumentException` | Attempt to generate certificate with unsupported key sizes (e.g. 512, 1234). | Throws `ArgumentException`. |
| **`TC-PDF-04`** | `TC_PDF_04_GenerateCertificate_WithFullDistinguishedName_ShouldPreserveSubjectDN` | Generate certificate with full enterprise X.500 Subject DN (`CN=..., OU=..., O=..., C=VN`). | Returns `true` (preserves all DN attributes). |
| **`TC-PDF-05`** | `TC_PDF_05_GenerateCertificate_WithCustomValidityDays_ShouldMatchExpiration` | Custom validity periods (30, 365, 730 days). | Expiration date matches UTC offset. |
| **`TC-PDF-06`** | `TC_PDF_06_GenerateCertificate_WithInvalidValidityDays_ShouldThrowArgumentException` | Non-positive validity days (0, -10). | Throws `ArgumentException`. |
| **`TC-PDF-07`** | `TC_PDF_07_GenerateCertificate_WithUnicodeVietnameseSubject_ShouldSucceed` | Vietnamese Unicode characters in Subject Name. | Returns `true` with accents preserved. |
| **`TC-PDF-08`** | `TC_PDF_08_GenerateCertificate_WithSpecialCharactersInPassword_ShouldSucceed` | Complex special characters in password. | Opens and signs successfully. |
| **`TC-PDF-09`** | `TC_PDF_09_GenerateCertificate_KeyUsageFlags_ShouldContainDigitalSignature` | Verify generated certificate X.509 Key Usage extensions. | Contains `X509KeyUsageFlags.DigitalSignature`. |
| **`TC-PDF-10`** | `TC_PDF_10_SignDataAndVerifyData_WithMatchingDatabasePublicKey_ShouldSucceed` | Generate detached signature and verify against DB public key. | Returns `true` (signature matches DB record). |
| **`TC-PDF-11`** | `TC_PDF_11_VerifyData_WithUnauthorizedAttackerKey_ShouldFail` | Attacker attempts to verify with unauthorized key. | Returns `false`. |
| **`TC-PDF-12`** | `TC_PDF_12_VerifyData_WhenDataIsTampered_ShouldFail` | 1 byte in document is tampered after signing. | Returns `false` (tampering detected). |
| **`TC-PDF-13`** | `TC_PDF_13_SignData_WithWrongPfxPassword_ShouldThrowException` | Sign data with incorrect PFX password. | Throws `Exception`. |
| **`TC-PDF-14`** | `TC_PDF_14_SignData_WithCorruptedPfxBytes_ShouldThrowException` | Sign data with corrupted PFX byte array. | Throws `Exception`. |
| **`TC-PDF-15`** | `TC_PDF_15_VerifyData_WithEmptyOrCorruptedData_ShouldReturnFalse` | Verify empty or corrupted data. | Returns `false`. |
| **`TC-PDF-16`** | `TC_PDF_16_VerifyData_WithEmptyOrCorruptedSignature_ShouldReturnFalse` | Verify empty or corrupted signature bytes. | Returns `false`. |
| **`TC-PDF-17`** | `TC_PDF_17_VerifyData_WithEmptyOrCorruptedPublicKey_ShouldReturnFalse` | Verify empty or mismatched public key. | Returns `false`. |
| **`TC-PDF-18`** | `TC_PDF_18_VerifyData_ConcurrentMultiThreaded_ShouldAllSucceed` | Concurrently verify signature across 30 simultaneous worker threads. | Returns `true` across all 30 threads. |
| **`TC-PDF-19`** | `TC_PDF_19_VerifyData_BatchMultiplePublicKeys_ShouldCorrectlyIdentifyMatchingKey` | Batch test signature against 1 legitimate key and 4 impostor keys. | Returns `true` only for matching key. |
| **`TC-PDF-20`** | `TC_PDF_20_StampVisualSignature_WithCustomCoordinates_ShouldSucceed` | Stamp visual signature box at custom (X, Y, Width, Height) position. | Returns stamped PDF byte array. |
| **`TC-PDF-21`** | `TC_PDF_21_StampVisualSignature_WithInvalidPageIndex_ShouldThrowArgumentOutOfRangeException` | Stamp visual signature on out-of-range page index. | Throws `ArgumentOutOfRangeException`. |
| **`TC-PDF-22`** | `TC_PDF_22_StampVisualSignature_WithVietnameseUnicodeText_ShouldSucceed` | Stamp visual signature with Vietnamese Unicode accents. | Renders Unicode text without error. |
| **`TC-PDF-23`** | `TC_PDF_23_SetFont_WithValidFontPath_ShouldSucceed` | Register custom TrueType font file path. | Executes without exception. |
| **`TC-PDF-24`** | `TC_PDF_24_SetFont_WithNonExistentFontPath_ShouldThrowFileNotFoundException` | Attempt to register non-existent font file path. | Throws `FileNotFoundException`. |
| **`TC-PDF-25`** | `TC_PDF_25_SetFont_WithNullOrWhitespaceFontPath_ShouldThrowFileNotFoundException` | Attempt to register null/empty font path. | Throws `FileNotFoundException`. |
| **`TC-PDF-26`** | `TC_PDF_26_HybridWorkflow_SequentialTwoSigners_BothVisualAndCryptoShouldSucceed` | Complete sequential hybrid workflow (Accountant + Director). | Returns `true` for all signers and visual output. |

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

    // POST /api/digitalsignature/stamp-and-sign
    [HttpPost("stamp-and-sign")]
    public async Task<IActionResult> StampAndSign(
        [FromForm] IFormFile pdfFile,
        [FromForm] IFormFile pfxFile,
        [FromForm] string password,
        [FromForm] string signerName,
        [FromForm] string reason = "Approved Contract",
        [FromForm] string location = "Ho Chi Minh City",
        [FromForm] double? x = null,
        [FromForm] double? y = null)
    {
        if (pdfFile == null || pfxFile == null)
        {
            return BadRequest("Both PDF document and PFX key file are required.");
        }

        // Read files into memory
        using var pdfMs = new MemoryStream();
        await pdfFile.CopyToAsync(pdfMs);
        byte[] inputPdfBytes = pdfMs.ToArray();

        using var pfxMs = new MemoryStream();
        await pfxFile.CopyToAsync(pfxMs);
        byte[] pfxBytes = pfxMs.ToArray();

        // 1. Stamp visual signature box on PDF
        byte[] stampedPdfBytes = PdfSigner.StampVisualSignature(
            inputPdfBytes,
            signerName: signerName,
            reason: reason,
            location: location,
            x: x,
            y: y);

        // 2. Generate detached cryptographic signature (1.1 KB)
        byte[] signatureBytes = PdfSigner.SignData(stampedPdfBytes, pfxBytes, password);

        // Save signatureBytes (1.1 KB) to your Database:
        // await _signatureDb.SaveSignatureAsync(documentId, userId, signatureBytes);

        return Ok(new
        {
            Message = "Document stamped and signed successfully!",
            SignatureHex = Convert.ToHexString(signatureBytes),
            StampedPdfBase64 = Convert.ToBase64String(stampedPdfBytes)
        });
    }

    // POST /api/digitalsignature/verify-data
    [HttpPost("verify-data")]
    public async Task<IActionResult> VerifyData(
        [FromForm] IFormFile pdfFile,
        [FromForm] string signatureHex,
        [FromForm] string userId)
    {
        if (pdfFile == null || string.IsNullOrWhiteSpace(signatureHex))
        {
            return BadRequest("PDF file and signature hex are required.");
        }

        // 1. Fetch user's registered Public Key from Database
        // byte[] userPublicKey = await _userDb.GetPublicKeyAsync(userId);
        byte[] userPublicKey = ...;

        using var ms = new MemoryStream();
        await pdfFile.CopyToAsync(ms);
        byte[] pdfBytes = ms.ToArray();
        byte[] signatureBytes = Convert.FromHexString(signatureHex);

        // 2. Verify cryptographic integrity & match against database key
        bool isValid = PdfSigner.VerifyData(pdfBytes, signatureBytes, userPublicKey);

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
