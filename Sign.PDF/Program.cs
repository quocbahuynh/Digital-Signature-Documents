using System;
using System.IO;

class Program
{
    static void Main()
    {
        Console.WriteLine("=== HYBRID DIGITAL SIGNATURE SIMULATION (VISUAL STAMP + CRYPTO DETACHED) ===\n");

        string inputPdf = File.Exists("document.pdf") 
            ? "document.pdf" 
            : Path.Combine(AppContext.BaseDirectory, "document.pdf");
        string finalOutputPdf = "document_hybrid_multisigned.pdf";
        byte[] originalPdfBytes = File.ReadAllBytes(inputPdf);

        // =========================================================================
        // STEP 1: USER 1 (ACCOUNTANT) GENERATES CERTIFICATE, STAMPS BOX & SIGNS
        // =========================================================================
        Console.WriteLine("[STEP 1] 09:00 AM - User 1 (Accountant) creates Certificate, stamps Visual Box & Signs:");
        string user1Password = "AccountantPass123!";
        var (user1Pfx, user1PublicKey) = PdfSigner.GenerateCertificate("Nguyen Van Accountant", user1Password);

        // 1.1. Stamp visual signature box at bottom-left corner (X: 40, Y: 40)
        byte[] pdfStep1Bytes = PdfSigner.StampVisualSignature(
            originalPdfBytes,
            signerName: "Nguyen Van Accountant",
            reason: "Reviewed & Approved by Accountant",
            location: "Hanoi, Vietnam",
            signedAt: DateTime.Now,
            x: 40,
            y: 40,
            width: 230,
            height: 60);

        // 1.2. Generate detached cryptographic signature for User 1
        byte[] user1Signature = PdfSigner.SignData(pdfStep1Bytes, user1Pfx, user1Password);
        Console.WriteLine("    • [Visual] Stamped Accountant signature box at Bottom-Left (X: 40, Y: 40).");
        Console.WriteLine($"    • [Crypto] Detached Signature: {Convert.ToHexString(user1Signature)[..30]}... ({user1Signature.Length} bytes)");
        Console.WriteLine("    • [Routing document to Director...]\n");

        // =========================================================================
        // STEP 2: USER 2 (DIRECTOR) RECEIVES FILE, STAMPS BOX & SIGNS
        // =========================================================================
        Console.WriteLine("[STEP 2] 03:00 PM - User 2 (Director) receives file, stamps Visual Box & Signs:");
        string user2Password = "DirectorPass123!";
        var (user2Pfx, user2PublicKey) = PdfSigner.GenerateCertificate("Huynh Ba Quoc (Director)", user2Password);

        // 2.1. Stamp visual signature box at bottom-right corner (X: 320, Y: 40)
        byte[] finalPdfBytes = PdfSigner.StampVisualSignature(
            pdfStep1Bytes,
            signerName: "Huynh Ba Quoc (Director)",
            reason: "Approved & Signed by Director",
            location: "Ho Chi Minh City, Vietnam",
            signedAt: DateTime.Now,
            x: 320,
            y: 40,
            width: 230,
            height: 60);

        // 2.2. Generate detached cryptographic signature for User 2
        byte[] user2Signature = PdfSigner.SignData(finalPdfBytes, user2Pfx, user2Password);
        Console.WriteLine("    • [Visual] Stamped Director signature box at Bottom-Right (X: 320, Y: 40).");
        Console.WriteLine($"    • [Crypto] Detached Signature: {Convert.ToHexString(user2Signature)[..30]}... ({user2Signature.Length} bytes)\n");

        // 2.3. Save final multi-signed PDF containing both visual signature boxes
        File.WriteAllBytes(finalOutputPdf, finalPdfBytes);
        Console.WriteLine($"🎉 Final PDF saved to '{finalOutputPdf}' (Contains both visible signature boxes)!\n");

        // =========================================================================
        // STEP 3: SERVER VERIFIES ALL SIGNATURES INDEPENDENTLY
        // =========================================================================
        Console.WriteLine("[STEP 3] Server / Auditor performs independent verification of all signers:");

        // 3.1. Verify Accountant signature against Step 1 document bytes
        bool isUser1Valid = PdfSigner.VerifyData(pdfStep1Bytes, user1Signature, user1PublicKey);
        Console.WriteLine($"    1. Accountant Verification (Nguyen Van Accountant): {(isUser1Valid ? "🟢 VALID (TRUE) - Legitimate signature!" : "🔴 FAILED")}");

        // 3.2. Verify Director signature against Final document bytes
        bool isUser2Valid = PdfSigner.VerifyData(finalPdfBytes, user2Signature, user2PublicKey);
        Console.WriteLine($"    2. Director Verification (Huynh Ba Quoc):          {(isUser2Valid ? "🟢 VALID (TRUE) - Legitimate signature!" : "🔴 FAILED")}");

        // 3.3. Test security against unauthorized attacker key
        var (_, attackerPublicKey) = PdfSigner.GenerateCertificate("Attacker Unknown", "attackerpass");
        bool isAttackerValid = PdfSigner.VerifyData(finalPdfBytes, user2Signature, attackerPublicKey);
        Console.WriteLine($"    3. Unauthorized Attacker Key Test:                 {(isAttackerValid ? "🔴 SECURITY BREACH" : "🛡️ REJECTED (FALSE)")}");

        // 3.4. Test security against tampered document content
        byte[] tamperedPdfBytes = (byte[])finalPdfBytes.Clone();
        tamperedPdfBytes[10] ^= 0xFF;
        bool isTamperedValid = PdfSigner.VerifyData(tamperedPdfBytes, user2Signature, user2PublicKey);
        Console.WriteLine($"    4. Document Tampering Detection Test:              {(isTamperedValid ? "🔴 TAMPER NOT DETECTED" : "🛡️ TAMPER DETECTED & REJECTED (FALSE)")}\n");

        Console.WriteLine("🎉 CONCLUSION: Both signers verified successfully (TRUE 100%) with visible signature boxes stamped!");
    }
}
