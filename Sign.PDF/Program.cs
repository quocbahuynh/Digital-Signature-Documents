using System;
using System.Collections.Generic;
using System.IO;

class Program
{
    static void Main()
    {
        Console.WriteLine("=== CO-SIGNING DIGITAL SIGNATURE SIMULATION (METHOD 4 - RFC 5652) ===\n");

        string inputPdf = File.Exists("document.pdf") 
            ? "document.pdf" 
            : Path.Combine(AppContext.BaseDirectory, "document.pdf");
        string outputPdf = "document_cosigned.pdf";
        byte[] inputPdfBytes = File.ReadAllBytes(inputPdf);

        // 1. Generate keys for User 1 (Accountant) and User 2 (Director)
        string user1Password = "AccountantPass123!";
        var (user1Pfx, user1PublicKey) = PdfSigner.GenerateCertificate("Nguyen Van Accountant", user1Password);

        string user2Password = "DirectorPass123!";
        var (user2Pfx, user2PublicKey) = PdfSigner.GenerateCertificate("Huynh Ba Quoc (Director)", user2Password);

        // Unrelated Attacker key
        var (_, attackerPublicKey) = PdfSigner.GenerateCertificate("Attacker Unknown", "attackerpass");

        Console.WriteLine("[1] Co-Signers List:");
        Console.WriteLine("    • Signer 1: 'Nguyen Van Accountant' (Accountant Review)");
        Console.WriteLine("    • Signer 2: 'Huynh Ba Quoc (Director)' (Director Approval)\n");

        // 2. Co-Sign PDF using SignMulti (embeds both digital signatures in 1 single CMS container)
        Console.WriteLine("[2] Co-signing 'document.pdf' with both signers in 1 CMS container in RAM...");
        var credentials = new List<PdfSigner.PdfSignerCredential>
        {
            new PdfSigner.PdfSignerCredential(user1Pfx, user1Password),
            new PdfSigner.PdfSignerCredential(user2Pfx, user2Password)
        };

        byte[] cosignedPdfBytes = PdfSigner.SignMulti(
            inputPdfBytes, 
            credentials, 
            reason: "Accountant Review & Director Approval", 
            location: "Ho Chi Minh City, Vietnam");

        File.WriteAllBytes(outputPdf, cosignedPdfBytes);
        Console.WriteLine($"✅ Co-signed document saved to '{outputPdf}'\n");

        // 3. Server Verifications
        Console.WriteLine("[3] Server Verification Results:");

        bool isUser1Valid = PdfSigner.Verify(cosignedPdfBytes, user1PublicKey);
        Console.WriteLine($"    • User 1 (Accountant) Verification: {(isUser1Valid ? "🎉 VALID & MATCHED!" : "❌ FAILED")}");

        bool isUser2Valid = PdfSigner.Verify(cosignedPdfBytes, user2PublicKey);
        Console.WriteLine($"    • User 2 (Director) Verification:   {(isUser2Valid ? "🎉 VALID & MATCHED!" : "❌ FAILED")}");

        bool isAttackerValid = PdfSigner.Verify(cosignedPdfBytes, attackerPublicKey);
        Console.WriteLine($"    • Attacker Verification:           {(isAttackerValid ? "❌ SECURITY BREACH" : "🛡️ REJECTED (FALSE)")}\n");
    }
}
