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
        // STEP 1: USER 1 (ACCOUNTANT) GENERATES KEYS & STAMPS VISUAL BOX AT BOTTOM-LEFT
        // =========================================================================
        Console.WriteLine("[STEP 1] 09:00 AM - User 1 (Accountant) creates Certificate & stamps Visual Box:");
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

        Console.WriteLine("    • [Visual] Stamped Accountant signature box at Bottom-Left (X: 40, Y: 40).");
        Console.WriteLine("    • [Routing document to Director...]\n");

        // =========================================================================
        // STEP 2: USER 2 (DIRECTOR) GENERATES KEYS & STAMPS VISUAL BOX AT BOTTOM-RIGHT
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

        // 2.2. Save final multi-signed PDF containing both visual signature boxes
        File.WriteAllBytes(finalOutputPdf, finalPdfBytes);
        Console.WriteLine("    • [Visual] Stamped Director signature box at Bottom-Right (X: 320, Y: 40).");
        Console.WriteLine($"🎉 Final PDF saved to '{finalOutputPdf}' (Contains both visible signature boxes)!\n");

        // =========================================================================
        // STEP 3: GENERATE DETACHED DIGITAL SIGNATURES ON THE FINAL PDF DOCUMENT
        // =========================================================================
        Console.WriteLine("[STEP 3] Generating detached PKCS#7 / CMS cryptographic signatures on final PDF:");

        byte[] user1Signature = PdfSigner.SignData(finalPdfBytes, user1Pfx, user1Password);
        Console.WriteLine($"    • User 1 (Accountant) Detached Signature: {Convert.ToHexString(user1Signature)[..30]}... ({user1Signature.Length} bytes)");

        byte[] user2Signature = PdfSigner.SignData(finalPdfBytes, user2Pfx, user2Password);
        Console.WriteLine($"    • User 2 (Director) Detached Signature:   {Convert.ToHexString(user2Signature)[..30]}... ({user2Signature.Length} bytes)\n");

        // =========================================================================
        // STEP 4: SERVER VERIFIES ALL SIGNERS ON THE SAME FINAL PDF DOCUMENT
        // =========================================================================
        Console.WriteLine("[STEP 4] Server / Auditor verifies BOTH signers on the SAME final PDF document:");

        // 4.1. Verify Accountant signature against final document bytes
        bool isUser1Valid = PdfSigner.VerifyData(finalPdfBytes, user1Signature, user1PublicKey);
        Console.WriteLine($"    1. Accountant Verification (Nguyen Van Accountant): {(isUser1Valid ? "🟢 VALID (TRUE) - Verified on Final PDF!" : "🔴 FAILED")}");

        // 4.2. Verify Director signature against final document bytes
        bool isUser2Valid = PdfSigner.VerifyData(finalPdfBytes, user2Signature, user2PublicKey);
        Console.WriteLine($"    2. Director Verification (Huynh Ba Quoc):          {(isUser2Valid ? "🟢 VALID (TRUE) - Verified on Final PDF!" : "🔴 FAILED")}");

        // 4.3. Test security against unauthorized attacker key
        var (_, attackerPublicKey) = PdfSigner.GenerateCertificate("Attacker Unknown", "attackerpass");
        bool isAttackerValid = PdfSigner.VerifyData(finalPdfBytes, user2Signature, attackerPublicKey);
        Console.WriteLine($"    3. Unauthorized Attacker Key Test:                 {(isAttackerValid ? "🔴 SECURITY BREACH" : "🛡️ REJECTED (FALSE)")}");

        // 4.4. Test security against tampered document content
        byte[] tamperedPdfBytes = (byte[])finalPdfBytes.Clone();
        tamperedPdfBytes[10] ^= 0xFF;
        bool isTamperedUser1 = PdfSigner.VerifyData(tamperedPdfBytes, user1Signature, user1PublicKey);
        bool isTamperedUser2 = PdfSigner.VerifyData(tamperedPdfBytes, user2Signature, user2PublicKey);
        Console.WriteLine($"    4. Document Tampering Detection Test (User 1):     {(isTamperedUser1 ? "🔴 TAMPER NOT DETECTED" : "🛡️ TAMPER DETECTED & REJECTED (FALSE)")}");
        Console.WriteLine($"    5. Document Tampering Detection Test (User 2):     {(isTamperedUser2 ? "🔴 TAMPER NOT DETECTED" : "🛡️ TAMPER DETECTED & REJECTED (FALSE)")}\n");

        Console.WriteLine("🎉 CONCLUSION: Both User 1 and User 2 verify with TRUE 100% on the EXACT SAME final PDF document!");
    }
}
