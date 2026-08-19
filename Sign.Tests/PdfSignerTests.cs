using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Xunit;

public class PdfSignerTests : IDisposable
{
    private readonly string _inputPdf;
    private readonly string _testPfx = "test_user_key.pfx";
    private readonly string _testPassword = "TestPassword123!";
    private readonly string _signedPdf = "test_signed.pdf";
    private readonly string _hackedPdf = "test_hacked.pdf";
    private readonly string _hackerPfx = "test_hacker_key.pfx";

    public PdfSignerTests()
    {
        _inputPdf = File.Exists("document.pdf") 
            ? "document.pdf" 
            : Path.Combine(AppContext.BaseDirectory, "document.pdf");
    }

    public void Dispose()
    {
        // Cleanup test artifacts
        TryDeleteFile(_testPfx);
        TryDeleteFile(_hackerPfx);
        TryDeleteFile(_signedPdf);
        TryDeleteFile(_hackedPdf);
    }

    private static void TryDeleteFile(string path)
    {
        if (File.Exists(path))
        {
            try { File.Delete(path); } catch { }
        }
    }

    [Fact]
    public void TC_PDF_01_GenerateCertificate_ShouldReturnPfxBytesAndPublicKey()
    {
        // Act
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("Test User", _testPassword);

        // Assert
        Assert.NotNull(pfxBytes);
        Assert.NotEmpty(pfxBytes);
        Assert.NotNull(publicKeyBytes);
        Assert.NotEmpty(publicKeyBytes);

        // Verify PFX is valid and opens with password
        using var cert = new X509Certificate2(pfxBytes, _testPassword);
        Assert.Contains("Test User", cert.Subject);
        Assert.True(cert.HasPrivateKey);
    }

    [Fact]
    public void TC_PDF_02_SignAndVerify_WithMatchingDatabasePublicKey_ShouldSucceed()
    {
        // Arrange
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("Huynh Ba Quoc", _testPassword);

        // Act: Sign in-memory bytes
        byte[] signedBytes = PdfSigner.Sign(inputBytes, pfxBytes, _testPassword, reason: "Approved Contract");
        File.WriteAllBytes(_signedPdf, signedBytes);
        bool isValid = PdfSigner.Verify(signedBytes, publicKeyBytes);

        // Assert
        Assert.True(File.Exists(_signedPdf), "Signed PDF file should exist.");
        Assert.True(isValid, "Signature should be valid and match Database Public Key.");
    }

    [Fact]
    public void TC_PDF_03_Verify_WithUnauthorizedAttackerKey_ShouldFail()
    {
        // Arrange: User generates legitimate key stored in DB
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (_, legitimatePublicKeyBytes) = PdfSigner.GenerateCertificate("Legitimate User", _testPassword);

        // Act: Hacker signs with their own key
        var (hackerPfx, _) = PdfSigner.GenerateCertificate("Hacker X", "hackerpass");
        byte[] hackedBytes = PdfSigner.Sign(inputBytes, hackerPfx, "hackerpass", reason: "Unauthorized");
        File.WriteAllBytes(_hackedPdf, hackedBytes);

        // Server verifies against Legitimate User's DB Public Key
        bool isValid = PdfSigner.Verify(hackedBytes, legitimatePublicKeyBytes);

        // Assert
        Assert.False(isValid, "Verification must fail when PDF was signed by an unauthorized key.");
    }

    [Fact]
    public void TC_PDF_04_Verify_WhenSignedDocumentIsTampered_ShouldFail()
    {
        // Arrange: Sign legitimate document
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("Tamper Test", _testPassword);
        byte[] signedBytes = PdfSigner.Sign(inputBytes, pfxBytes, _testPassword);

        // Act: Tamper with 1 byte in the signed PDF file content
        byte[] tamperedBytes = (byte[])signedBytes.Clone();
        tamperedBytes[100] = (byte)(tamperedBytes[100] ^ 0xFF); // Invert 1 byte

        bool isValid = PdfSigner.Verify(tamperedBytes, publicKeyBytes);

        // Assert
        Assert.False(isValid, "Verification must fail when document content is altered after signing.");
    }

    [Fact]
    public void TC_PDF_05_Verify_WhenDocumentHasNoSignature_ShouldFail()
    {
        // Arrange
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (_, publicKeyBytes) = PdfSigner.GenerateCertificate("Test User", _testPassword);

        // Act: Verify unsigned original document
        bool isValid = PdfSigner.Verify(inputBytes, publicKeyBytes);

        // Assert
        Assert.False(isValid, "Verification must fail for unsigned documents.");
    }

    [Fact]
    public void TC_PDF_06_SignAndVerify_WithPfxBytes_ShouldSucceed()
    {
        // Arrange: Generate certificate returning PFX byte array
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("Huynh Ba Quoc", _testPassword);

        // Act: Sign directly with byte[] PFX
        byte[] signedBytes = PdfSigner.Sign(inputBytes, pfxBytes, _testPassword, reason: "Byte Array Signing Test");
        File.WriteAllBytes(_signedPdf, signedBytes);
        bool isValid = PdfSigner.Verify(signedBytes, publicKeyBytes);

        // Assert
        Assert.True(File.Exists(_signedPdf), "Signed PDF file should exist.");
        Assert.True(isValid, "Signature with PFX bytes should be valid and match Database Public Key.");
    }

    [Fact]
    public void TC_PDF_07_SignAndVerify_WithCustomFontPath_ShouldSucceed()
    {
        // Arrange
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("Custom Font User", _testPassword);
        string customFontPath = Path.Combine(AppContext.BaseDirectory, "Fonts", "Verdana.ttf");

        // Act: Sign with custom font path passed to Sign()
        byte[] signedBytes = PdfSigner.Sign(inputBytes, pfxBytes, _testPassword, reason: "Custom Font Test", customFontPath: customFontPath);
        File.WriteAllBytes(_signedPdf, signedBytes);
        bool isValid = PdfSigner.Verify(signedBytes, publicKeyBytes);

        // Assert
        Assert.True(File.Exists(_signedPdf), "Signed PDF should exist.");
        Assert.True(isValid, "PDF signed with custom font path should be valid.");
    }

    [Fact]
    public void TC_PDF_08_SignAndVerify_InMemoryBytes_ShouldSucceed()
    {
        // Arrange: Load input PDF entirely into memory
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("Memory User", _testPassword);

        // Act: Sign and verify purely in RAM without writing to disk
        byte[] signedBytes = PdfSigner.Sign(inputBytes, pfxBytes, _testPassword, reason: "In-Memory Signing Test");
        bool isValid = PdfSigner.Verify(signedBytes, publicKeyBytes);

        // Assert
        Assert.NotNull(signedBytes);
        Assert.NotEmpty(signedBytes);
        Assert.True(signedBytes.Length > inputBytes.Length, "Signed PDF bytes should contain signature data.");
        Assert.True(isValid, "In-memory verification against DB public key should succeed.");
    }

    [Theory]
    [InlineData(1024)]
    [InlineData(2048)]
    [InlineData(3072)]
    [InlineData(4096)]
    public void TC_PDF_09_GenerateCertificate_WithSupportedKeySizes_ShouldSucceed(int keySizeInBits)
    {
        // Act: Generate keys for each valid bit size
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("KeySize User", _testPassword, keySizeInBits);

        // Assert
        Assert.NotNull(pfxBytes);
        Assert.NotEmpty(pfxBytes);
        Assert.NotNull(publicKeyBytes);
        Assert.NotEmpty(publicKeyBytes);

        // Verify keypair can sign and verify
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        byte[] signedBytes = PdfSigner.Sign(inputBytes, pfxBytes, _testPassword, reason: $"KeySize {keySizeInBits} Test");
        bool isValid = PdfSigner.Verify(signedBytes, publicKeyBytes);
        Assert.True(isValid, $"Signature with {keySizeInBits}-bit key should be valid.");
    }

    [Theory]
    [InlineData(512)]
    [InlineData(1234)]
    [InlineData(8192)]
    public void TC_PDF_10_GenerateCertificate_WithInvalidKeySize_ShouldThrowArgumentException(int invalidKeySize)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
        {
            PdfSigner.GenerateCertificate("Invalid KeySize User", _testPassword, invalidKeySize);
        });
    }

    [Fact]
    public void TC_PDF_11_GenerateCertificate_WithFullX500DistinguishedName_ShouldSucceed()
    {
        // Arrange: Full enterprise X.500 Subject DN
        string enterpriseSubject = "CN=Huynh Ba Quoc, OU=IT Security, O=Enterprise Corp, C=VN";

        // Act
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate(enterpriseSubject, _testPassword);
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        byte[] signedBytes = PdfSigner.Sign(inputBytes, pfxBytes, _testPassword, reason: "Enterprise Signing Test");
        bool isValid = PdfSigner.Verify(signedBytes, publicKeyBytes);

        // Assert
        Assert.True(isValid, "PDF signed with full X.500 Subject DN should verify successfully.");
    }

    [Theory]
    [InlineData(30)]   // 30-day trial certificate
    [InlineData(365)]  // 1-year standard certificate
    [InlineData(730)]  // 2-year enterprise certificate
    public void TC_PDF_12_GenerateCertificate_WithCustomValidityDays_ShouldSucceed(int validityInDays)
    {
        // Act: Generate keys with custom validity period
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("Expiry User", _testPassword, validityInDays: validityInDays);

        // Assert: Compare in UTC to avoid local timezone offset differences
        using var cert = new X509Certificate2(pfxBytes, _testPassword);
        DateTime expectedNotAfterUtc = DateTime.UtcNow.AddDays(validityInDays);
        DateTime certNotAfterUtc = cert.NotAfter.ToUniversalTime();
        TimeSpan difference = certNotAfterUtc - expectedNotAfterUtc;

        // Verify expiry is within a few seconds of expected
        Assert.True(Math.Abs(difference.TotalMinutes) < 5, "Certificate expiration should match requested validityInDays.");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-10)]
    public void TC_PDF_13_GenerateCertificate_WithInvalidValidityDays_ShouldThrowArgumentException(int invalidDays)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
        {
            PdfSigner.GenerateCertificate("Invalid Expiry User", _testPassword, validityInDays: invalidDays);
        });
    }

    [Fact]
    public void TC_PDF_14_Sign_WithCustomPageIndexAndCoordinates_ShouldSucceed()
    {
        // Arrange
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("Page Position User", _testPassword);

        // Act: Sign on page 0 with custom rectangle (x: 50, y: 50, width: 200, height: 80)
        byte[] signedBytes = PdfSigner.Sign(
            inputBytes, 
            pfxBytes, 
            _testPassword, 
            pageIndex: 0, 
            x: 50, 
            y: 50, 
            width: 200, 
            height: 80);
        bool isValid = PdfSigner.Verify(signedBytes, publicKeyBytes);

        // Assert
        Assert.NotNull(signedBytes);
        Assert.NotEmpty(signedBytes);
        Assert.True(isValid, "PDF signed on custom page and position should verify successfully.");
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(999)]
    public void TC_PDF_15_Sign_WithInvalidPageIndex_ShouldThrowArgumentOutOfRangeException(int invalidPageIndex)
    {
        // Arrange
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (pfxBytes, _) = PdfSigner.GenerateCertificate("Invalid Page User", _testPassword);

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            PdfSigner.Sign(inputBytes, pfxBytes, _testPassword, pageIndex: invalidPageIndex);
        });
    }

    [Fact]
    public void TC_PDF_16_CoSigning_WithMultipleSignersInSingleCmsContainer_BothSignaturesShouldVerifySuccessfully()
    {
        // Arrange
        byte[] originalPdfBytes = File.ReadAllBytes(_inputPdf);

        // User 1: Accountant
        var (user1Pfx, user1PublicKey) = PdfSigner.GenerateCertificate("Nguyen Van Accountant", _testPassword);
        
        // User 2: Director
        var (user2Pfx, user2PublicKey) = PdfSigner.GenerateCertificate("Huynh Ba Director", _testPassword);

        // Attacker / Unrelated party
        var (_, attackerPublicKey) = PdfSigner.GenerateCertificate("Attacker Unknown", _testPassword);

        var credentials = new System.Collections.Generic.List<PdfSigner.PdfSignerCredential>
        {
            new PdfSigner.PdfSignerCredential(user1Pfx, _testPassword),
            new PdfSigner.PdfSignerCredential(user2Pfx, _testPassword)
        };

        // Act: Co-Sign with both credentials in a single CMS container
        byte[] cosignedBytes = PdfSigner.SignMulti(
            originalPdfBytes, 
            credentials, 
            reason: "Accountant Review & Director Approval", 
            location: "Ho Chi Minh City, Vietnam");

        // Server Verifications
        bool isUser1Valid = PdfSigner.Verify(cosignedBytes, user1PublicKey);
        bool isUser2Valid = PdfSigner.Verify(cosignedBytes, user2PublicKey);
        bool isAttackerValid = PdfSigner.Verify(cosignedBytes, attackerPublicKey);

        // Assert: Both User 1 and User 2 are valid, Attacker is rejected
        Assert.True(isUser1Valid, "User 1 (Accountant) signature must verify successfully.");
        Assert.True(isUser2Valid, "User 2 (Director) signature must verify successfully.");
        Assert.False(isAttackerValid, "Attacker key must not match any valid signature on the document.");
    }

    [Fact]
    public void TC_PDF_17_SetFont_WithValidFontPath_ShouldSucceed()
    {
        // Arrange
        string validFontPath = Path.Combine(AppContext.BaseDirectory, "Fonts", "Verdana.ttf");

        // Act & Assert (should not throw)
        var exception = Record.Exception(() => PdfSigner.SetFont(validFontPath));
        Assert.Null(exception);
    }

    [Fact]
    public void TC_PDF_18_SetFont_WithNonExistentFontPath_ShouldThrowFileNotFoundException()
    {
        // Act & Assert
        Assert.Throws<FileNotFoundException>(() =>
        {
            PdfSigner.SetFont("non_existent_font_12345.ttf");
        });
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void TC_PDF_19_SetFont_WithNullOrWhitespaceFontPath_ShouldThrowFileNotFoundException(string? invalidPath)
    {
        // Act & Assert
        Assert.Throws<FileNotFoundException>(() =>
        {
            PdfSigner.SetFont(invalidPath!);
        });
    }

    [Fact]
    public void TC_PDF_20_GenerateCertificate_WithUnicodeVietnameseSubject_ShouldSucceed()
    {
        // Arrange: Vietnamese Unicode subject
        string vnSubject = "Nguyễn Văn Ánh (Công Ty Cổ Phần Công Nghệ)";

        // Act
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate(vnSubject, _testPassword);
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        byte[] signedBytes = PdfSigner.Sign(inputBytes, pfxBytes, _testPassword);
        bool isValid = PdfSigner.Verify(signedBytes, publicKeyBytes);

        // Assert
        using var cert = new X509Certificate2(pfxBytes, _testPassword);
        Assert.Contains(vnSubject, cert.Subject);
        Assert.True(isValid, "PDF with Vietnamese Unicode subject name should sign and verify.");
    }

    [Fact]
    public void TC_PDF_21_GenerateCertificate_WithSpecialCharactersInPassword_ShouldSucceed()
    {
        // Arrange: Complex password with symbols
        string complexPass = "P@$$w0rd!#%^&*()_+-=[]{}|;:,.<>?";

        // Act
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("Complex Pass User", complexPass);
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        byte[] signedBytes = PdfSigner.Sign(inputBytes, pfxBytes, complexPass);
        bool isValid = PdfSigner.Verify(signedBytes, publicKeyBytes);

        // Assert
        Assert.True(isValid, "PDF signed with complex special-character password should verify successfully.");
    }

    [Fact]
    public void TC_PDF_22_GenerateCertificate_KeyUsageFlags_ShouldContainDigitalSignature()
    {
        // Act
        var (pfxBytes, _) = PdfSigner.GenerateCertificate("KeyUsage User", _testPassword);

        // Assert
        using var cert = new X509Certificate2(pfxBytes, _testPassword);
        var keyUsage = cert.Extensions
            .OfType<X509KeyUsageExtension>()
            .FirstOrDefault();

        Assert.NotNull(keyUsage);
        Assert.True(keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature));
    }

    [Fact]
    public void TC_PDF_23_Sign_WithWrongPfxPassword_ShouldThrowException()
    {
        // Arrange
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (pfxBytes, _) = PdfSigner.GenerateCertificate("Wrong Pass User", _testPassword);

        // Act & Assert
        Assert.ThrowsAny<Exception>(() =>
        {
            PdfSigner.Sign(inputBytes, pfxBytes, "WrongPasswordHere");
        });
    }

    [Fact]
    public void TC_PDF_24_Sign_WithCorruptedPfxBytes_ShouldThrowException()
    {
        // Arrange
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        byte[] corruptedPfxBytes = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };

        // Act & Assert
        Assert.ThrowsAny<Exception>(() =>
        {
            PdfSigner.Sign(inputBytes, corruptedPfxBytes, _testPassword);
        });
    }

    [Fact]
    public void TC_PDF_25_Sign_WithCorruptedInputPdfBytes_ShouldThrowException()
    {
        // Arrange
        var (pfxBytes, _) = PdfSigner.GenerateCertificate("Corrupted PDF User", _testPassword);
        byte[] corruptedPdfBytes = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD };

        // Act & Assert
        Assert.ThrowsAny<Exception>(() =>
        {
            PdfSigner.Sign(corruptedPdfBytes, pfxBytes, _testPassword);
        });
    }

    [Fact]
    public void TC_PDF_26_Sign_WithNonExistentCustomFontPath_ShouldThrowFileNotFoundException()
    {
        // Arrange
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (pfxBytes, _) = PdfSigner.GenerateCertificate("Custom Font Fail User", _testPassword);

        // Act & Assert
        Assert.Throws<FileNotFoundException>(() =>
        {
            PdfSigner.Sign(inputBytes, pfxBytes, _testPassword, customFontPath: "does_not_exist.ttf");
        });
    }

    [Fact]
    public void TC_PDF_27_Sign_WithVietnameseUnicodeReasonAndLocation_ShouldSucceed()
    {
        // Arrange
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("VN Locale User", _testPassword);

        // Act
        byte[] signedBytes = PdfSigner.Sign(
            inputBytes, 
            pfxBytes, 
            _testPassword, 
            reason: "Đã kiểm tra và phê duyệt hợp đồng kinh tế", 
            location: "Thành phố Hồ Chí Minh, Việt Nam");
        bool isValid = PdfSigner.Verify(signedBytes, publicKeyBytes);

        // Assert
        Assert.True(isValid, "PDF signed with Vietnamese Unicode reason & location should verify.");
    }

    [Fact]
    public void TC_PDF_28_Sign_OnMultiPagePdf_WithSpecificPageIndices_ShouldSucceed()
    {
        // Arrange: Create a 3-page PDF in memory
        using var multiDoc = new PdfSharp.Pdf.PdfDocument();
        multiDoc.AddPage(); // Page 0
        multiDoc.AddPage(); // Page 1
        multiDoc.AddPage(); // Page 2
        using var ms = new MemoryStream();
        multiDoc.Save(ms);
        byte[] multiPagePdfBytes = ms.ToArray();

        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("MultiPage User", _testPassword);

        // Act: Sign on Page 1 (middle page)
        byte[] signedBytes = PdfSigner.Sign(
            multiPagePdfBytes, 
            pfxBytes, 
            _testPassword, 
            pageIndex: 1, 
            x: 50, 
            y: 50, 
            width: 200, 
            height: 60);
        bool isValid = PdfSigner.Verify(signedBytes, publicKeyBytes);

        // Assert
        Assert.True(isValid, "Signing on intermediate page of multi-page PDF should succeed.");
    }

    [Fact]
    public void TC_PDF_29_Verify_WithEmptyOrCorruptedSignedPdfBytes_ShouldReturnFalse()
    {
        // Arrange
        var (_, publicKeyBytes) = PdfSigner.GenerateCertificate("Corrupt Verify User", _testPassword);
        byte[] emptyBytes = Array.Empty<byte>();
        byte[] garbageBytes = new byte[] { 0x01, 0x02, 0x03, 0x04 };

        // Act
        bool isNullOrEmptyValid = PdfSigner.Verify(emptyBytes, publicKeyBytes);
        bool isGarbageValid = PdfSigner.Verify(garbageBytes, publicKeyBytes);

        // Assert
        Assert.False(isNullOrEmptyValid);
        Assert.False(isGarbageValid);
    }

    [Fact]
    public void TC_PDF_30_Verify_WithEmptyOrMismatchedPublicKeyBytes_ShouldReturnFalse()
    {
        // Arrange
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (pfxBytes, _) = PdfSigner.GenerateCertificate("Mismatch Key User", _testPassword);
        byte[] signedBytes = PdfSigner.Sign(inputBytes, pfxBytes, _testPassword);

        // Act
        bool isEmptyKeyValid = PdfSigner.Verify(signedBytes, Array.Empty<byte>());
        bool isRandomKeyValid = PdfSigner.Verify(signedBytes, new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });

        // Assert
        Assert.False(isEmptyKeyValid);
        Assert.False(isRandomKeyValid);
    }

    [Fact]
    public void TC_PDF_31_Verify_WhenSignatureContentsBlockIsTampered_ShouldReturnFalse()
    {
        // Arrange
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("Contents Tamper User", _testPassword);
        byte[] signedBytes = PdfSigner.Sign(inputBytes, pfxBytes, _testPassword);

        // Act: Tamper with hex string within /Contents
        string pdfText = System.Text.Encoding.ASCII.GetString(signedBytes);
        int contentsIndex = pdfText.IndexOf("/Contents");
        Assert.True(contentsIndex > 0, "PDF must contain /Contents dictionary.");

        byte[] tamperedBytes = (byte[])signedBytes.Clone();
        // Modify a byte inside the hex string (skip "/Contents<" header)
        tamperedBytes[contentsIndex + 15] = (byte)(tamperedBytes[contentsIndex + 15] == 'A' ? 'B' : 'A');

        bool isValid = PdfSigner.Verify(tamperedBytes, publicKeyBytes);

        // Assert
        Assert.False(isValid, "Tampered /Contents hex signature must fail verification.");
    }

    [Fact]
    public void TC_PDF_32_Verify_WithNonPdfGarbageBytes_ShouldReturnFalse()
    {
        // Arrange
        var (_, publicKeyBytes) = PdfSigner.GenerateCertificate("Garbage Test User", _testPassword);
        byte[] plainTextBytes = System.Text.Encoding.UTF8.GetBytes("This is a plain text file, not a PDF document.");

        // Act
        bool isValid = PdfSigner.Verify(plainTextBytes, publicKeyBytes);

        // Assert
        Assert.False(isValid, "Non-PDF plain text must return false in Verify.");
    }

    [Fact]
    public void TC_PDF_33_Verify_ConcurrentMultiThreaded_ShouldAllSucceed()
    {
        // Arrange: Sign a legitimate document
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("Concurrent User", _testPassword);
        byte[] signedBytes = PdfSigner.Sign(inputBytes, pfxBytes, _testPassword);

        // Act: Run 30 concurrent threads verifying the same document simultaneously
        bool[] results = new bool[30];
        System.Threading.Tasks.Parallel.For(0, 30, i =>
        {
            results[i] = PdfSigner.Verify(signedBytes, publicKeyBytes);
        });

        // Assert: All 30 concurrent verifications must return true
        Assert.All(results, isValid => Assert.True(isValid, "All concurrent verifications must return true."));
    }

    [Fact]
    public void TC_PDF_34_Verify_BatchMultiplePublicKeys_ShouldCorrectlyIdentifyMatchingKey()
    {
        // Arrange: 1 Legitimate User and 4 Impostors
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (legitimatePfx, legitimateKey) = PdfSigner.GenerateCertificate("Legitimate User", _testPassword);
        
        var (_, impostor1Key) = PdfSigner.GenerateCertificate("Impostor 1", _testPassword);
        var (_, impostor2Key) = PdfSigner.GenerateCertificate("Impostor 2", _testPassword);
        var (_, impostor3Key) = PdfSigner.GenerateCertificate("Impostor 3", _testPassword);
        var (_, impostor4Key) = PdfSigner.GenerateCertificate("Impostor 4", _testPassword);

        byte[] signedBytes = PdfSigner.Sign(inputBytes, legitimatePfx, _testPassword);

        // Act: Batch verification across all 5 candidate public keys
        bool verifyLegitimate = PdfSigner.Verify(signedBytes, legitimateKey);
        bool verifyImpostor1 = PdfSigner.Verify(signedBytes, impostor1Key);
        bool verifyImpostor2 = PdfSigner.Verify(signedBytes, impostor2Key);
        bool verifyImpostor3 = PdfSigner.Verify(signedBytes, impostor3Key);
        bool verifyImpostor4 = PdfSigner.Verify(signedBytes, impostor4Key);

        // Assert: Only legitimate key is true, all impostors are false
        Assert.True(verifyLegitimate, "Legitimate key must verify successfully.");
        Assert.False(verifyImpostor1, "Impostor 1 must fail verification.");
        Assert.False(verifyImpostor2, "Impostor 2 must fail verification.");
        Assert.False(verifyImpostor3, "Impostor 3 must fail verification.");
        Assert.False(verifyImpostor4, "Impostor 4 must fail verification.");
    }
}
