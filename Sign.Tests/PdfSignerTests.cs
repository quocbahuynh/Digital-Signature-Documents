using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Xunit;

public class PdfSignerTests : IDisposable
{
    private readonly string _inputPdf;
    private readonly string _testPassword = "TestPassword123!";

    public PdfSignerTests()
    {
        _inputPdf = File.Exists("document.pdf") 
            ? "document.pdf" 
            : Path.Combine(AppContext.BaseDirectory, "document.pdf");
    }

    public void Dispose()
    {
        // Cleanup any temporary files if created
    }

    // =========================================================================
    // SECTION 1: CERTIFICATE GENERATION TESTS (X.509 RSA PKCS#12)
    // =========================================================================

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

        using var cert = new X509Certificate2(pfxBytes, _testPassword);
        Assert.Contains("Test User", cert.Subject);
        Assert.True(cert.HasPrivateKey);
    }

    [Theory]
    [InlineData(1024)]
    [InlineData(2048)]
    [InlineData(3072)]
    [InlineData(4096)]
    public void TC_PDF_02_GenerateCertificate_WithAllowedKeySizes_ShouldSucceed(int keySize)
    {
        // Act
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("KeySize Test", _testPassword, keySizeInBits: keySize);

        // Assert
        using var cert = new X509Certificate2(pfxBytes, _testPassword);
        Assert.NotNull(cert);
        Assert.NotEmpty(publicKeyBytes);
    }

    [Theory]
    [InlineData(512)]
    [InlineData(1234)]
    [InlineData(8192)]
    public void TC_PDF_03_GenerateCertificate_WithInvalidKeySize_ShouldThrowArgumentException(int invalidKeySize)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
        {
            PdfSigner.GenerateCertificate("Invalid KeySize", _testPassword, keySizeInBits: invalidKeySize);
        });
    }

    [Fact]
    public void TC_PDF_04_GenerateCertificate_WithFullDistinguishedName_ShouldPreserveSubjectDN()
    {
        // Arrange
        string fullDN = "CN=Huynh Ba Quoc, OU=Engineering, O=MyCompany, C=VN";

        // Act
        var (pfxBytes, _) = PdfSigner.GenerateCertificate(fullDN, _testPassword);

        // Assert
        using var cert = new X509Certificate2(pfxBytes, _testPassword);
        Assert.Contains("Huynh Ba Quoc", cert.Subject);
        Assert.Contains("Engineering", cert.Subject);
        Assert.Contains("MyCompany", cert.Subject);
        Assert.Contains("VN", cert.Subject);
    }

    [Theory]
    [InlineData(30)]
    [InlineData(365)]
    [InlineData(730)]
    public void TC_PDF_05_GenerateCertificate_WithCustomValidityDays_ShouldMatchExpiration(int validityDays)
    {
        // Act
        var (pfxBytes, _) = PdfSigner.GenerateCertificate("Validity Test", _testPassword, validityInDays: validityDays);

        // Assert
        using var cert = new X509Certificate2(pfxBytes, _testPassword);
        var expectedEnd = DateTime.UtcNow.AddDays(validityDays);
        var actualEnd = cert.NotAfter.ToUniversalTime();

        Assert.Equal(expectedEnd.Year, actualEnd.Year);
        Assert.Equal(expectedEnd.Month, actualEnd.Month);
        Assert.Equal(expectedEnd.Day, actualEnd.Day);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-10)]
    public void TC_PDF_06_GenerateCertificate_WithInvalidValidityDays_ShouldThrowArgumentException(int invalidDays)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
        {
            PdfSigner.GenerateCertificate("Invalid Validity", _testPassword, validityInDays: invalidDays);
        });
    }

    [Fact]
    public void TC_PDF_07_GenerateCertificate_WithUnicodeVietnameseSubject_ShouldSucceed()
    {
        // Arrange
        string vietnameseName = "Nguyễn Văn Đạt - Giám Đốc Kỹ Thuật";

        // Act
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate(vietnameseName, _testPassword);

        // Assert
        using var cert = new X509Certificate2(pfxBytes, _testPassword);
        Assert.Contains(vietnameseName, cert.Subject);
        Assert.NotEmpty(publicKeyBytes);
    }

    [Fact]
    public void TC_PDF_08_GenerateCertificate_WithSpecialCharactersInPassword_ShouldSucceed()
    {
        // Arrange
        string complexPassword = "P@$$w0rd!#%^&*()_+~`|}{[]:;?><,./";

        // Act
        var (pfxBytes, _) = PdfSigner.GenerateCertificate("Special Char User", complexPassword);

        // Assert
        using var cert = new X509Certificate2(pfxBytes, complexPassword);
        Assert.NotNull(cert);
        Assert.True(cert.HasPrivateKey);
    }

    [Fact]
    public void TC_PDF_09_GenerateCertificate_KeyUsageFlags_ShouldContainDigitalSignature()
    {
        // Act
        var (pfxBytes, _) = PdfSigner.GenerateCertificate("KeyUsage Test", _testPassword);

        // Assert
        using var cert = new X509Certificate2(pfxBytes, _testPassword);
        bool hasDigitalSignatureFlag = false;
        foreach (var extension in cert.Extensions)
        {
            if (extension is X509KeyUsageExtension keyUsage)
            {
                if ((keyUsage.KeyUsages & X509KeyUsageFlags.DigitalSignature) != 0)
                {
                    hasDigitalSignatureFlag = true;
                }
            }
        }

        Assert.True(hasDigitalSignatureFlag, "Certificate must contain X509KeyUsageFlags.DigitalSignature.");
    }

    // =========================================================================
    // SECTION 2: DETACHED DIGITAL SIGNING & VERIFICATION (SignData & VerifyData)
    // =========================================================================

    [Fact]
    public void TC_PDF_10_SignDataAndVerifyData_WithMatchingDatabasePublicKey_ShouldSucceed()
    {
        // Arrange
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("Huynh Ba Quoc", _testPassword);

        // Act
        byte[] signatureBytes = PdfSigner.SignData(inputBytes, pfxBytes, _testPassword);
        bool isValid = PdfSigner.VerifyData(inputBytes, signatureBytes, publicKeyBytes);

        // Assert
        Assert.NotNull(signatureBytes);
        Assert.NotEmpty(signatureBytes);
        Assert.True(isValid, "Detached signature must be valid and match Database Public Key.");
    }

    [Fact]
    public void TC_PDF_11_VerifyData_WithUnauthorizedAttackerKey_ShouldFail()
    {
        // Arrange
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (legitimatePfx, _) = PdfSigner.GenerateCertificate("Legitimate User", _testPassword);
        var (_, attackerPublicKey) = PdfSigner.GenerateCertificate("Attacker Unknown", "attackerpass");

        // Act
        byte[] signatureBytes = PdfSigner.SignData(inputBytes, legitimatePfx, _testPassword);
        bool isValid = PdfSigner.VerifyData(inputBytes, signatureBytes, attackerPublicKey);

        // Assert
        Assert.False(isValid, "Verification must fail when checked against an unauthorized attacker key.");
    }

    [Fact]
    public void TC_PDF_12_VerifyData_WhenDataIsTampered_ShouldFail()
    {
        // Arrange
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("Tamper Test", _testPassword);
        byte[] signatureBytes = PdfSigner.SignData(inputBytes, pfxBytes, _testPassword);

        // Act: Tamper with 1 byte in the data
        byte[] tamperedBytes = (byte[])inputBytes.Clone();
        tamperedBytes[0] ^= 0xFF;
        bool isValid = PdfSigner.VerifyData(tamperedBytes, signatureBytes, publicKeyBytes);

        // Assert
        Assert.False(isValid, "Verification must fail when data has been altered.");
    }

    [Fact]
    public void TC_PDF_13_SignData_WithWrongPfxPassword_ShouldThrowException()
    {
        // Arrange
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (pfxBytes, _) = PdfSigner.GenerateCertificate("Password Test", _testPassword);

        // Act & Assert
        Assert.ThrowsAny<Exception>(() =>
        {
            PdfSigner.SignData(inputBytes, pfxBytes, "WrongPassword999!");
        });
    }

    [Fact]
    public void TC_PDF_14_SignData_WithCorruptedPfxBytes_ShouldThrowException()
    {
        // Arrange
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        byte[] corruptedPfxBytes = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };

        // Act & Assert
        Assert.ThrowsAny<Exception>(() =>
        {
            PdfSigner.SignData(inputBytes, corruptedPfxBytes, _testPassword);
        });
    }

    [Fact]
    public void TC_PDF_15_VerifyData_WithEmptyOrCorruptedData_ShouldReturnFalse()
    {
        // Arrange
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("Corrupt Data Test", _testPassword);
        byte[] validData = new byte[] { 1, 2, 3, 4, 5 };
        byte[] signatureBytes = PdfSigner.SignData(validData, pfxBytes, _testPassword);

        // Act
        bool verifyEmpty = PdfSigner.VerifyData(Array.Empty<byte>(), signatureBytes, publicKeyBytes);
        bool verifyGarbage = PdfSigner.VerifyData(new byte[] { 9, 9, 9 }, signatureBytes, publicKeyBytes);

        // Assert
        Assert.False(verifyEmpty, "Empty data must return false.");
        Assert.False(verifyGarbage, "Corrupted data must return false.");
    }

    [Fact]
    public void TC_PDF_16_VerifyData_WithEmptyOrCorruptedSignature_ShouldReturnFalse()
    {
        // Arrange
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (_, publicKeyBytes) = PdfSigner.GenerateCertificate("Corrupt Sig Test", _testPassword);

        // Act
        bool verifyEmpty = PdfSigner.VerifyData(inputBytes, Array.Empty<byte>(), publicKeyBytes);
        bool verifyGarbage = PdfSigner.VerifyData(inputBytes, new byte[] { 0x30, 0x82, 0x01 }, publicKeyBytes);

        // Assert
        Assert.False(verifyEmpty, "Empty signature must return false.");
        Assert.False(verifyGarbage, "Corrupted signature must return false.");
    }

    [Fact]
    public void TC_PDF_17_VerifyData_WithEmptyOrCorruptedPublicKey_ShouldReturnFalse()
    {
        // Arrange
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (pfxBytes, _) = PdfSigner.GenerateCertificate("Key Test", _testPassword);
        byte[] signatureBytes = PdfSigner.SignData(inputBytes, pfxBytes, _testPassword);

        // Act
        bool verifyEmpty = PdfSigner.VerifyData(inputBytes, signatureBytes, Array.Empty<byte>());
        bool verifyGarbage = PdfSigner.VerifyData(inputBytes, signatureBytes, new byte[] { 0x01, 0x02, 0x03 });

        // Assert
        Assert.False(verifyEmpty, "Empty public key must return false.");
        Assert.False(verifyGarbage, "Mismatched public key must return false.");
    }

    [Fact]
    public void TC_PDF_18_VerifyData_ConcurrentMultiThreaded_ShouldAllSucceed()
    {
        // Arrange
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("MultiThread User", _testPassword);
        byte[] signatureBytes = PdfSigner.SignData(inputBytes, pfxBytes, _testPassword);

        int concurrentThreads = 30;
        bool[] results = new bool[concurrentThreads];

        // Act: Run 30 simultaneous threads verifying the signature
        Parallel.For(0, concurrentThreads, i =>
        {
            results[i] = PdfSigner.VerifyData(inputBytes, signatureBytes, publicKeyBytes);
        });

        // Assert
        for (int i = 0; i < concurrentThreads; i++)
        {
            Assert.True(results[i], $"Thread {i} verification must be true.");
        }
    }

    [Fact]
    public void TC_PDF_19_VerifyData_BatchMultiplePublicKeys_ShouldCorrectlyIdentifyMatchingKey()
    {
        // Arrange: 1 Legitimate User and 4 Impostors
        byte[] inputBytes = File.ReadAllBytes(_inputPdf);
        var (legitimatePfx, legitimateKey) = PdfSigner.GenerateCertificate("Legitimate User", _testPassword);
        
        var (_, impostor1Key) = PdfSigner.GenerateCertificate("Impostor 1", _testPassword);
        var (_, impostor2Key) = PdfSigner.GenerateCertificate("Impostor 2", _testPassword);
        var (_, impostor3Key) = PdfSigner.GenerateCertificate("Impostor 3", _testPassword);
        var (_, impostor4Key) = PdfSigner.GenerateCertificate("Impostor 4", _testPassword);

        byte[] signatureBytes = PdfSigner.SignData(inputBytes, legitimatePfx, _testPassword);

        // Act
        bool verifyLegitimate = PdfSigner.VerifyData(inputBytes, signatureBytes, legitimateKey);
        bool verifyImpostor1 = PdfSigner.VerifyData(inputBytes, signatureBytes, impostor1Key);
        bool verifyImpostor2 = PdfSigner.VerifyData(inputBytes, signatureBytes, impostor2Key);
        bool verifyImpostor3 = PdfSigner.VerifyData(inputBytes, signatureBytes, impostor3Key);
        bool verifyImpostor4 = PdfSigner.VerifyData(inputBytes, signatureBytes, impostor4Key);

        // Assert
        Assert.True(verifyLegitimate, "Legitimate key must verify successfully.");
        Assert.False(verifyImpostor1, "Impostor 1 must fail.");
        Assert.False(verifyImpostor2, "Impostor 2 must fail.");
        Assert.False(verifyImpostor3, "Impostor 3 must fail.");
        Assert.False(verifyImpostor4, "Impostor 4 must fail.");
    }

    // =========================================================================
    // SECTION 3: VISUAL SIGNATURE STAMPING TESTS (StampVisualSignature)
    // =========================================================================

    [Fact]
    public void TC_PDF_20_StampVisualSignature_WithCustomCoordinates_ShouldSucceed()
    {
        // Arrange
        byte[] originalBytes = File.ReadAllBytes(_inputPdf);

        // Act
        byte[] stampedBytes = PdfSigner.StampVisualSignature(
            originalBytes,
            signerName: "Huynh Ba Quoc",
            reason: "Contract Approved",
            location: "Ho Chi Minh City",
            x: 50,
            y: 50,
            width: 250,
            height: 70);

        // Assert
        Assert.NotNull(stampedBytes);
        Assert.True(stampedBytes.Length > originalBytes.Length, "Stamped PDF must be larger than original.");
    }

    [Fact]
    public void TC_PDF_21_StampVisualSignature_WithInvalidPageIndex_ShouldThrowArgumentOutOfRangeException()
    {
        // Arrange
        byte[] originalBytes = File.ReadAllBytes(_inputPdf);

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            PdfSigner.StampVisualSignature(originalBytes, "User A", pageIndex: 999);
        });

        Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            PdfSigner.StampVisualSignature(originalBytes, "User A", pageIndex: -1);
        });
    }

    [Fact]
    public void TC_PDF_22_StampVisualSignature_WithVietnameseUnicodeText_ShouldSucceed()
    {
        // Arrange
        byte[] originalBytes = File.ReadAllBytes(_inputPdf);

        // Act
        byte[] stampedBytes = PdfSigner.StampVisualSignature(
            originalBytes,
            signerName: "Nguyễn Văn Đạt (Kế Toán Trưởng)",
            reason: "Đã kiểm tra hóa đơn và duyệt chi",
            location: "Hà Nội, Việt Nam");

        // Assert
        Assert.NotNull(stampedBytes);
        Assert.NotEmpty(stampedBytes);
    }

    [Fact]
    public void TC_PDF_23_SetFont_WithValidFontPath_ShouldSucceed()
    {
        // Arrange
        string fontPath = Path.Combine(AppContext.BaseDirectory, "Fonts", "Verdana.ttf");

        // Act & Assert
        if (File.Exists(fontPath))
        {
            PdfSigner.SetFont(fontPath, "CustomVerdana");
        }
    }

    [Fact]
    public void TC_PDF_24_SetFont_WithNonExistentFontPath_ShouldThrowFileNotFoundException()
    {
        // Act & Assert
        Assert.Throws<FileNotFoundException>(() =>
        {
            PdfSigner.SetFont("NonExistentFolder/FakeFont.ttf");
        });
    }

    [Fact]
    public void TC_PDF_25_SetFont_WithNullOrWhitespaceFontPath_ShouldThrowFileNotFoundException()
    {
        // Act & Assert
        Assert.Throws<FileNotFoundException>(() =>
        {
            PdfSigner.SetFont("");
        });
    }

    // =========================================================================
    // SECTION 4: HYBRID MULTI-SIGNER WORKFLOW (StampVisual + SignData + VerifyData)
    // =========================================================================

    [Fact]
    public void TC_PDF_26_HybridWorkflow_SequentialTwoSigners_BothVisualAndCryptoShouldSucceed()
    {
        // Arrange
        byte[] originalBytes = File.ReadAllBytes(_inputPdf);

        // Step 1: User 1 (Accountant) stamps visual box at bottom-left
        var (user1Pfx, user1PublicKey) = PdfSigner.GenerateCertificate("Nguyen Van Accountant", _testPassword);
        byte[] step1PdfBytes = PdfSigner.StampVisualSignature(
            originalBytes,
            signerName: "Nguyen Van Accountant",
            reason: "Reviewed by Accountant",
            location: "Hanoi",
            x: 40,
            y: 40,
            width: 220,
            height: 60);

        // Step 2: User 2 (Director) stamps visual box at bottom-right
        var (user2Pfx, user2PublicKey) = PdfSigner.GenerateCertificate("Huynh Ba Director", _testPassword);
        byte[] finalPdfBytes = PdfSigner.StampVisualSignature(
            step1PdfBytes,
            signerName: "Huynh Ba Director",
            reason: "Approved by Director",
            location: "Ho Chi Minh City",
            x: 320,
            y: 40,
            width: 220,
            height: 60);

        // Step 3: Both users sign the final document
        byte[] user1Signature = PdfSigner.SignData(finalPdfBytes, user1Pfx, _testPassword);
        byte[] user2Signature = PdfSigner.SignData(finalPdfBytes, user2Pfx, _testPassword);

        // Assert: Detached cryptographic verification for both users on the final PDF
        bool isUser1Valid = PdfSigner.VerifyData(finalPdfBytes, user1Signature, user1PublicKey);
        bool isUser2Valid = PdfSigner.VerifyData(finalPdfBytes, user2Signature, user2PublicKey);

        Assert.True(isUser1Valid, "User 1 (Accountant) must verify on the final PDF.");
        Assert.True(isUser2Valid, "User 2 (Director) must verify on the final PDF.");

        // Assert: Attacker rejection
        var (_, attackerPublicKey) = PdfSigner.GenerateCertificate("Attacker", _testPassword);
        bool isAttackerValid = PdfSigner.VerifyData(finalPdfBytes, user2Signature, attackerPublicKey);
        Assert.False(isAttackerValid, "Attacker public key must fail verification.");
    }
}
