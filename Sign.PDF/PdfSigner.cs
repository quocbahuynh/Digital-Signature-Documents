using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using PdfSharp.Drawing;
using PdfSharp.Fonts;
using PdfSharp.Pdf;
using PdfSharp.Pdf.IO;

public static class PdfSigner
{
    // Global font resolver instance registered once for the PDFsharp library
    private static readonly CustomFontResolver FontResolver = new CustomFontResolver();

    // Static constructor: Executed once when the PdfSigner class is first loaded into memory
    static PdfSigner()
    {
        GlobalFontSettings.FontResolver = FontResolver;
    }

    /// <summary>
    /// Configures a custom font file path for PDF signature text annotations.
    /// </summary>
    public static void SetFont(string fontPath, string fontName = "CustomFont")
    {
        FontResolver.SetFont(fontPath, fontName);
    }

    /// <summary>
    /// Generates a self-signed X.509 Digital Certificate: Returns Private Key PFX as raw byte array and Public Key for Database storage.
    /// Supports plain user name (e.g. "Huynh Ba Quoc") or full X.500 Subject DN (e.g. "CN=Huynh Ba Quoc, O=Company, C=VN").
    /// Supported key sizes: 1024, 2048 (default), 3072, 4096 bits.
    /// Expiration: Customizable via validityInDays (default: 365 days / 1 year).
    /// </summary>
    public static (byte[] pfxBytes, byte[] publicKeyBytes) GenerateCertificate(
        string subjectOrUserName, 
        string password, 
        int keySizeInBits = 2048,
        int validityInDays = 365)
    {
        // Validate key size: Only allow 1024, 2048, 3072, or 4096 bits
        if (keySizeInBits != 1024 && keySizeInBits != 2048 && keySizeInBits != 3072 && keySizeInBits != 4096)
        {
            throw new ArgumentException(
                "Invalid RSA key size. Supported key sizes are 1024, 2048, 3072, or 4096 bits.", 
                nameof(keySizeInBits));
        }

        // Validate validity period: Must be positive
        if (validityInDays <= 0)
        {
            throw new ArgumentException(
                "Certificate validity must be greater than 0 days.", 
                nameof(validityInDays));
        }

        // Step 1: Initialize RSA key generator with the specified bit size
        RSA rsa = RSA.Create(keySizeInBits);

        // Step 2: Format Certificate Subject Name (supports plain name or full X.500 DN)
        string subject;
        if (subjectOrUserName.Contains("=") == true)
        {
            subject = subjectOrUserName;
        }
        else
        {
            subject = "CN=" + subjectOrUserName;
        }
        X500DistinguishedName subjectName = new X500DistinguishedName(subject);

        // Step 3: Create Certificate Request using SHA-256
        CertificateRequest request = new CertificateRequest(
            subjectName,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Step 4: Add Digital Signature usage flag
        X509KeyUsageExtension keyUsage = new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true);
        request.CertificateExtensions.Add(keyUsage);

        // Step 5: Set certificate validity period (valid for validityInDays starting from yesterday)
        DateTimeOffset startDate = DateTimeOffset.UtcNow.AddDays(-1);
        DateTimeOffset endDate = DateTimeOffset.UtcNow.AddDays(validityInDays);

        // Step 6: Create self-signed certificate
        X509Certificate2 certificate = request.CreateSelfSigned(startDate, endDate);

        // Step 7: Extract Public Key for Database storage
        byte[] publicKeyBytes = certificate.GetPublicKey();

        // Step 8: Export Private Key PFX protected by password as raw byte array
        byte[] pfxBytes = certificate.Export(X509ContentType.Pfx, password);

        // Step 9: Dispose cryptographic objects
        certificate.Dispose();
        rsa.Dispose();

        // Return generated keypair
        return (pfxBytes, publicKeyBytes);
    }

    /// <summary>
    /// CLIENT-SIDE / SERVER-SIDE (IN-MEMORY): Stamps a visible signature box onto a PDF page in RAM without modifying cryptographic signature structures.
    /// Ideal for stamping visual approval boxes incrementally during multi-signer workflows before generating detached cryptographic signatures.
    /// </summary>
    public static byte[] StampVisualSignature(
        byte[] inputPdfBytes,
        string signerName,
        string reason = "Approved",
        string location = "Ho Chi Minh City",
        DateTime? signedAt = null,
        int? pageIndex = null,
        double? x = null,
        double? y = null,
        double? width = null,
        double? height = null,
        string? customFontPath = null)
    {
        // Step 1: Configure custom font if provided
        if (string.IsNullOrWhiteSpace(customFontPath) == false)
        {
            SetFont(customFontPath);
        }

        // Step 2: Open input PDF document from memory stream in Modify mode
        MemoryStream inMs = new MemoryStream(inputPdfBytes);
        PdfDocument doc = PdfReader.Open(inMs, PdfDocumentOpenMode.Modify);

        // Step 3: Determine target page (default: last page)
        int targetPageIndex;
        if (pageIndex.HasValue == true)
        {
            if (pageIndex.Value < 0 || pageIndex.Value >= doc.PageCount)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(pageIndex),
                    $"Page index {pageIndex.Value} is out of range. Document has {doc.PageCount} pages (0 to {doc.PageCount - 1}).");
            }
            targetPageIndex = pageIndex.Value;
        }
        else
        {
            targetPageIndex = doc.PageCount - 1;
        }

        PdfPage page = doc.Pages[targetPageIndex];

        // Step 4: Calculate visual box coordinates (converts bottom-left PDF offset to top-left XGraphics coordinate)
        double boxX = x.HasValue ? x.Value : 310;
        double defaultHeight = height.HasValue ? height.Value : 60;
        double defaultWidth = width.HasValue ? width.Value : 230;
        double boxY = y.HasValue 
            ? (page.Height.Point - y.Value - defaultHeight) 
            : (page.Height.Point - 100);

        DateTime date = signedAt.HasValue ? signedAt.Value : DateTime.Now;

        // Step 5: Render visible signature box onto the page using XGraphics
        using (XGraphics gfx = XGraphics.FromPdfPage(page))
        {
            string fontName = FontResolver.CurrentFontName;
            XFont fontRegular = new XFont(fontName, 7.5, XFontStyleEx.Regular);
            XFont fontBold = new XFont(fontName, 7.5, XFontStyleEx.Bold);
            XBrush textBrush = XBrushes.Black;

            double currentY = boxY + 12;
            gfx.DrawString($"Signed by: {signerName}", fontBold, textBrush, new XPoint(boxX, currentY));
            currentY += 12;
            gfx.DrawString($"Location: {location}", fontRegular, textBrush, new XPoint(boxX, currentY));
            currentY += 12;
            gfx.DrawString($"Reason: {reason}", fontRegular, textBrush, new XPoint(boxX, currentY));
            currentY += 12;
            gfx.DrawString($"Date: {date:dd/MM/yyyy HH:mm:ss}", fontRegular, textBrush, new XPoint(boxX, currentY));
        }

        // Step 6: Save stamped PDF document to memory stream
        MemoryStream outMs = new MemoryStream();
        doc.Save(outMs);
        byte[] stampedPdfBytes = outMs.ToArray();

        // Step 7: Dispose memory streams and document
        outMs.Dispose();
        doc.Dispose();
        inMs.Dispose();

        // Step 8: Return stamped PDF byte array
        return stampedPdfBytes;
    }

    /// <summary>
    /// CLIENT-SIDE (IN-MEMORY): Generates a standalone detached PKCS#7 / CMS digital signature for arbitrary data (file/bytes) in RAM.
    /// Does not modify or embed into the original data, ideal for multi-step approval workflows stored in database.
    /// </summary>
    public static byte[] SignData(byte[] dataBytes, byte[] pfxBytes, string password)
    {
        // Step 1: Load and unlock the X.509 Certificate from PFX bytes using the password (cross-platform compatible)
        X509Certificate2 userCert = new X509Certificate2(pfxBytes, password, X509KeyStorageFlags.Exportable);

        // Step 2: Package raw data bytes into a CMS ContentInfo structure
        ContentInfo contentInfo = new ContentInfo(dataBytes);

        // Step 3: Initialize SignedCms in detached mode (true)
        SignedCms signedCms = new SignedCms(contentInfo, true);

        // Step 4: Configure CMS Signer using the X.509 Certificate and SHA-256 hash algorithm
        CmsSigner cmsSigner = new CmsSigner(userCert);
        cmsSigner.DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1", "SHA256");

        // Step 5: Compute the cryptographic digital signature
        signedCms.ComputeSignature(cmsSigner);

        // Step 6: Encode the CMS structure into a standard PKCS#7 ASN.1 byte array
        byte[] signatureBytes = signedCms.Encode();

        // Step 7: Dispose cryptographic objects
        userCert.Dispose();

        // Step 8: Return the detached PKCS#7 signature byte array
        return signatureBytes;
    }

    /// <summary>
    /// SERVER-SIDE (IN-MEMORY): Verifies a standalone detached PKCS#7 / CMS digital signature against the original data and Database Public Key.
    /// </summary>
    public static bool VerifyData(byte[] dataBytes, byte[] signatureBytes, byte[] publicKeyBytes)
    {
        try
        {
            // Step 1: Package raw data bytes into a CMS ContentInfo structure
            ContentInfo contentInfo = new ContentInfo(dataBytes);

            // Step 2: Initialize SignedCms in detached mode (true)
            SignedCms signedCms = new SignedCms(contentInfo, true);

            // Step 3: Decode detached PKCS#7 signature bytes
            signedCms.Decode(signatureBytes);

            // Step 4: Verify cryptographic integrity (detect data or signature tampering)
            signedCms.CheckSignature(true);

            // Step 5: Verify matching Database Public Key across signers
            foreach (SignerInfo signerInfo in signedCms.SignerInfos)
            {
                X509Certificate2? signerCert = signerInfo.Certificate;
                if (signerCert != null)
                {
                    byte[] pdfPublicKey = signerCert.GetPublicKey();
                    bool isMatched = pdfPublicKey.SequenceEqual(publicKeyBytes);
                    if (isMatched == true)
                    {
                        return true;
                    }
                }
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    // --- Private Helper Classes ---

    private class CustomFontResolver : IFontResolver
    {
        private string _fontName = "Verdana";
        private string? _customFontPath = null;

        public string CurrentFontName
        {
            get
            {
                return _fontName;
            }
        }

        public void SetFont(string fontPath, string fontName = "CustomFont")
        {
            string? resolvedPath = ResolveFontPath(fontPath);
            if (resolvedPath == null)
            {
                throw new FileNotFoundException($"Custom font file not found at: '{fontPath}'");
            }
            _customFontPath = resolvedPath;
            _fontName = fontName;
        }

        public FontResolverInfo? ResolveTypeface(string familyName, bool isBold, bool isItalic)
        {
            return new FontResolverInfo(_fontName);
        }

        public byte[]? GetFont(string faceName)
        {
            // 1. If user configured a custom font file path
            if (string.IsNullOrEmpty(_customFontPath) == false)
            {
                string? resolvedPath = ResolveFontPath(_customFontPath);
                if (resolvedPath != null)
                {
                    return File.ReadAllBytes(resolvedPath);
                }
            }

            // 2. Default fallback: Load from application folder ./Fonts/Verdana.ttf
            string defaultPath = Path.Combine(AppContext.BaseDirectory, "Fonts", "Verdana.ttf");
            string? resolvedDefaultPath = ResolveFontPath(defaultPath);
            if (resolvedDefaultPath != null)
            {
                return File.ReadAllBytes(resolvedDefaultPath);
            }

            return null;
        }

        /// <summary>
        /// Normalizes path separators (\ and /) and resolves cross-platform paths for Windows, Linux, and macOS.
        /// </summary>
        private static string? ResolveFontPath(string fontPath)
        {
            if (string.IsNullOrWhiteSpace(fontPath) == true)
            {
                return null;
            }

            // Step 1: Check raw path as provided
            if (File.Exists(fontPath) == true)
            {
                return fontPath;
            }

            // Step 2: Normalize directory separators (\ and /) for the current operating system
            string normalizedPath = fontPath
                .Replace('\\', Path.DirectorySeparatorChar)
                .Replace('/', Path.DirectorySeparatorChar);

            if (File.Exists(normalizedPath) == true)
            {
                return normalizedPath;
            }

            // Step 3: Check relative to application binary directory (AppContext.BaseDirectory)
            string appBasePath = Path.Combine(AppContext.BaseDirectory, normalizedPath);
            if (File.Exists(appBasePath) == true)
            {
                return appBasePath;
            }

            return null;
        }
    }
}
