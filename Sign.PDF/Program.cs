using System;
using System.IO;

class Program
{
    static void Main()
    {
        Console.WriteLine("=== DIGITAL SIGNATURE SIMULATION (CLIENT & DATABASE) ===\n");

        // 1. Generate certificate: returns Private Key (PFX byte array) and Database Public Key (byte array)
        string userPassword = "MySecurePassword123";
        var (pfxBytes, publicKeyBytes) = PdfSigner.GenerateCertificate("Huynh Ba Quoc", userPassword);
        Console.WriteLine($"[1] Generated User Private Key (PFX byte[]): {Convert.ToHexString(pfxBytes)[..40]}... (Length: {pfxBytes.Length} bytes)");
        Console.WriteLine($"    Database stored Public Key: {Convert.ToHexString(publicKeyBytes)[..40]}... (Length: {publicKeyBytes.Length} bytes)\n");

        // 2. Client signs PDF in RAM using their Private Key byte array
        string inputPdf = File.Exists("document.pdf") 
            ? "document.pdf" 
            : Path.Combine(AppContext.BaseDirectory, "document.pdf");
        string outputPdf = "document_signed.pdf";

        Console.WriteLine("[2] Client signs 'document.pdf' using PFX Private Key byte[] in RAM...");
        byte[] inputPdfBytes = File.ReadAllBytes(inputPdf);
        byte[] signedPdfBytes = PdfSigner.Sign(inputPdfBytes, pfxBytes, userPassword, reason: "Approved Contract");
        File.WriteAllBytes(outputPdf, signedPdfBytes);
        Console.WriteLine($"✅ Signed document saved to '{outputPdf}'\n");

        // 3. Server receives PDF and verifies against Database Public Key
        Console.WriteLine("[3] Server receives PDF and verifies against Database Public Key...");
        bool isValid = PdfSigner.Verify(signedPdfBytes, publicKeyBytes);
        if (isValid == true)
        {
            Console.WriteLine("🎉 Server: Signature VALID & MATCHES Database record (CN=Huynh Ba Quoc)!");
        }
        else
        {
            Console.WriteLine("❌ Server: Verification FAILED!");
        }
    }
}
