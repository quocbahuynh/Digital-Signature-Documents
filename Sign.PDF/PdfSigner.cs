using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using PdfSharp.Drawing;
using PdfSharp.Fonts;
using PdfSharp.Pdf;
using PdfSharp.Pdf.IO;
using PdfSharp.Pdf.Signatures;

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
    /// Represents a signer credential (PFX private key bytes + password) for co-signing documents.
    /// </summary>
    public class PdfSignerCredential
    {
        public byte[] PfxBytes { get; }
        public string Password { get; }

        public PdfSignerCredential(byte[] pfxBytes, string password)
        {
            PfxBytes = pfxBytes;
            Password = password;
        }
    }

    /// <summary>
    /// CLIENT-SIDE (IN-MEMORY): Signs a PDF byte array directly in RAM using raw PFX byte array.
    /// Supports custom reason, location, font, page index (0-based, default: last page), and coordinates (X, Y, Width, Height).
    /// </summary>
    public static byte[] Sign(
        byte[] inputPdfBytes, 
        byte[] pfxBytes, 
        string password, 
        string reason = "Approved", 
        string location = "Ho Chi Minh City", 
        string? customFontPath = null,
        int? pageIndex = null,
        double? x = null,
        double? y = null,
        double? width = null,
        double? height = null)
    {
        List<PdfSignerCredential> credentials = new List<PdfSignerCredential>
        {
            new PdfSignerCredential(pfxBytes, password)
        };

        return SignMulti(
            inputPdfBytes, 
            credentials, 
            reason, 
            location, 
            customFontPath, 
            pageIndex, 
            x, 
            y, 
            width, 
            height);
    }

    /// <summary>
    /// CLIENT-SIDE (IN-MEMORY): Co-signs a PDF byte array with MULTIPLE signers in a single PKCS#7 / CMS container (RFC 5652).
    /// All signers' digital signatures are cryptographically embedded and simultaneously verifiable on the document.
    /// </summary>
    public static byte[] SignMulti(
        byte[] inputPdfBytes, 
        IEnumerable<PdfSignerCredential> credentials, 
        string reason = "Approved", 
        string location = "Ho Chi Minh City", 
        string? customFontPath = null,
        int? pageIndex = null,
        double? x = null,
        double? y = null,
        double? width = null,
        double? height = null)
    {
        // Step 1: Configure custom font if provided
        if (string.IsNullOrWhiteSpace(customFontPath) == false)
        {
            SetFont(customFontPath);
        }

        // Step 2: Load and unlock all X.509 Certificates from credentials (cross-platform compatible)
        List<X509Certificate2> certificates = new List<X509Certificate2>();
        foreach (PdfSignerCredential cred in credentials)
        {
            X509Certificate2 cert = new X509Certificate2(cred.PfxBytes, cred.Password, X509KeyStorageFlags.Exportable);
            certificates.Add(cert);
        }

        // Step 3: Open the input PDF document from memory
        MemoryStream inMs = new MemoryStream(inputPdfBytes);
        PdfDocument doc = PdfReader.Open(inMs, PdfDocumentOpenMode.Modify);

        // Step 4: Configure visible signature options and coordinates
        DigitalSignatureOptions options = ConfigureVisibleSignatureOptions(
            doc.PageCount, 
            reason, 
            location, 
            pageIndex, 
            x, 
            y, 
            width, 
            height);

        // Step 5: Initialize multi-signer digital signer with all user certificates and attach to document
        SimpleDigitalSigner signer = new SimpleDigitalSigner(certificates);
        DigitalSignatureHandler.ForDocument(doc, signer, options);

        // Step 6: Save signed PDF document to output memory stream
        MemoryStream outMs = new MemoryStream();
        doc.Save(outMs);
        byte[] signedPdfBytes = outMs.ToArray();

        // Step 7: Dispose memory streams, document, and cryptographic objects
        outMs.Dispose();
        doc.Dispose();
        inMs.Dispose();
        foreach (X509Certificate2 cert in certificates)
        {
            cert.Dispose();
        }

        // Step 8: Return the signed PDF byte array
        return signedPdfBytes;
    }

    /// <summary>
    /// Helper: Configures visible digital signature options including target page validation and visual rectangle coordinates.
    /// </summary>
    private static DigitalSignatureOptions ConfigureVisibleSignatureOptions(
        int totalPageCount,
        string reason,
        string location,
        int? pageIndex,
        double? x,
        double? y,
        double? width,
        double? height)
    {
        // 1. Determine target page index (default: last page)
        int targetPageIndex;
        if (pageIndex.HasValue == true)
        {
            if (pageIndex.Value < 0 || pageIndex.Value >= totalPageCount)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(pageIndex),
                    $"Page index {pageIndex.Value} is out of range. Document has {totalPageCount} pages (0 to {totalPageCount - 1}).");
            }
            targetPageIndex = pageIndex.Value;
        }
        else
        {
            targetPageIndex = totalPageCount - 1;
        }

        // 2. Configure visual signature coordinates (default: bottom-right box)
        double sigX = x.HasValue ? x.Value : 310;
        double sigY = y.HasValue ? y.Value : 40;
        double sigWidth = width.HasValue ? width.Value : 260;
        double sigHeight = height.HasValue ? height.Value : 60;
        XRect signatureRectangle = new XRect(sigX, sigY, sigWidth, sigHeight);

        // 3. Construct DigitalSignatureOptions
        return new DigitalSignatureOptions
        {
            Reason = reason,
            Location = location,
            Rectangle = signatureRectangle,
            PageIndex = targetPageIndex
        };
    }

    /// <summary>
    /// SERVER-SIDE (IN-MEMORY): Verifies that the signed PDF contains a valid cryptographic signature matching the Database Public Key.
    /// Supports single-signer and multi-signer co-signed documents (RFC 5652).
    /// </summary>
    public static bool Verify(byte[] signedPdfBytes, byte[] publicKeyBytes)
    {
        try
        {
            string pdfText = System.Text.Encoding.ASCII.GetString(signedPdfBytes);

            // Step 1: Locate active /ByteRange and /Contents in the PDF (scans from end of file)
            Match byteRangeMatch = Regex.Match(pdfText, @"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", RegexOptions.RightToLeft);
            Match contentsMatch = Regex.Match(pdfText, @"/Contents\s*<([0-9A-Fa-f]+)>", RegexOptions.RightToLeft);

            if (byteRangeMatch.Success == false || contentsMatch.Success == false)
            {
                return false;
            }

            // Step 2: Parse byte offsets and lengths of the signed content
            int offset1 = int.Parse(byteRangeMatch.Groups[1].Value);
            int length1 = int.Parse(byteRangeMatch.Groups[2].Value);
            int offset2 = int.Parse(byteRangeMatch.Groups[3].Value);
            int length2 = int.Parse(byteRangeMatch.Groups[4].Value);

            if (offset1 + length1 > signedPdfBytes.Length || offset2 + length2 > signedPdfBytes.Length)
            {
                return false;
            }

            // Step 3: Extract the raw signed content bytes
            byte[] signedBytes = new byte[length1 + length2];
            Buffer.BlockCopy(signedPdfBytes, offset1, signedBytes, 0, length1);
            Buffer.BlockCopy(signedPdfBytes, offset2, signedBytes, length1, length2);

            // Step 4: Extract and decode PKCS#7 signature bytes from hexadecimal
            string hexContent = contentsMatch.Groups[1].Value;
            byte[] signatureBytes = Convert.FromHexString(hexContent);

            // Step 5: Verify cryptographic integrity (detect tampering)
            ContentInfo contentInfo = new ContentInfo(signedBytes);
            SignedCms signedCms = new SignedCms(contentInfo, true);
            signedCms.Decode(signatureBytes);
            signedCms.CheckSignature(true);

            // Step 6: Verify matching Database Public Key across all co-signers in the CMS container
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

    /// <summary>
    /// Helper: Implements PDFsharp's IDigitalSigner interface to generate PKCS#7 / CMS detached signatures for single or multiple signers.
    /// </summary>
    private class SimpleDigitalSigner : IDigitalSigner
    {
        private readonly IReadOnlyList<X509Certificate2> _certificates;

        public SimpleDigitalSigner(IReadOnlyList<X509Certificate2> certificates)
        {
            _certificates = certificates;
        }

        public SimpleDigitalSigner(X509Certificate2 singleCertificate)
        {
            _certificates = new List<X509Certificate2> { singleCertificate };
        }

        /// <summary>
        /// Gets the certificate display name for the signature field annotation.
        /// </summary>
        public string CertificateName
        {
            get
            {
                List<string> names = new List<string>();
                foreach (X509Certificate2 cert in _certificates)
                {
                    string? commonName = cert.GetNameInfo(X509NameType.SimpleName, false);
                    if (string.IsNullOrWhiteSpace(commonName) == false)
                    {
                        names.Add(commonName);
                    }
                }

                if (names.Count == 0)
                {
                    return "Signer";
                }
                return string.Join(" & ", names);
            }
        }

        /// <summary>
        /// Returns the estimated maximum byte size allocated for the digital signature in the PDF structure.
        /// </summary>
        public Task<int> GetSignatureSizeAsync()
        {
            int allocatedSizeInBytes = Math.Max(4096, _certificates.Count * 4096);
            return Task.FromResult(allocatedSizeInBytes);
        }

        /// <summary>
        /// Calculates the cryptographic PKCS#7 / CMS digital signature for the PDF document content stream.
        /// Supports embedding multiple co-signers in a single CMS structure (RFC 5652).
        /// </summary>
        public Task<byte[]> GetSignatureAsync(Stream contentStream)
        {
            // Step 1: Ensure the underlying stream position is at the beginning (0)
            PropertyInfo? streamProperty = contentStream.GetType().GetProperty(
                "Stream", 
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);

            if (streamProperty != null)
            {
                object? propertyValue = streamProperty.GetValue(contentStream);
                if (propertyValue is Stream internalStream)
                {
                    try
                    {
                        internalStream.Position = 0;
                    }
                    catch
                    {
                        // Ignore if internal stream does not support position setting
                    }
                }
            }

            // Step 2: Read raw document content bytes using a standard buffer loop (compatible with RangedStream)
            MemoryStream memoryStream = new MemoryStream();
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = contentStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                memoryStream.Write(buffer, 0, bytesRead);
            }
            byte[] documentBytes = memoryStream.ToArray();
            memoryStream.Dispose();

            // Step 3: Package raw document bytes into a CMS ContentInfo structure
            ContentInfo contentInfo = new ContentInfo(documentBytes);

            // Step 4: Initialize SignedCms in detached mode (true) so the signature is stored separately
            SignedCms signedCms = new SignedCms(contentInfo, true);

            // Step 5: Compute cryptographic digital signatures for ALL co-signers in the container
            foreach (X509Certificate2 cert in _certificates)
            {
                CmsSigner cmsSigner = new CmsSigner(cert);
                cmsSigner.DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1", "SHA256");
                signedCms.ComputeSignature(cmsSigner);
            }

            // Step 6: Encode the multi-signer CMS structure into a standard PKCS#7 ASN.1 byte array
            byte[] pkcs7SignatureBytes = signedCms.Encode();

            // Step 7: Return the signature bytes as an asynchronous Task result
            return Task.FromResult(pkcs7SignatureBytes);
        }
    }

    private class CustomFontResolver : IFontResolver
    {
        private string _fontName = "Verdana";
        private string? _customFontPath = null;

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
