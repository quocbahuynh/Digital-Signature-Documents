using System;
using System.IO;

class Program
{
    static void Main()
    {
        Console.WriteLine("=== MULTI-SIGNER DIGITAL SIGNATURE SIMULATION ===\n");

        string inputPdf = File.Exists("document.pdf") 
            ? "document.pdf" 
            : Path.Combine(AppContext.BaseDirectory, "document.pdf");
        string outputPdf = "document_multisigned.pdf";
        byte[] currentPdfBytes = File.ReadAllBytes(inputPdf);

        // -------------------------------------------------------------
        // Step 1: Signer 1 (Accountant) generates keys & signs bottom-left
        // -------------------------------------------------------------
        string user1Password = "AccountantPass123!";
        var (user1Pfx, user1PublicKey) = PdfSigner.GenerateCertificate("Nguyen Van Accountant", user1Password);
        Console.WriteLine("[1] Signer 1 (Accountant): 'Nguyen Van Accountant'");
        Console.WriteLine($"    Signing at Bottom-Left Box (X: 40, Y: 40, Width: 230, Height: 60)...");

        currentPdfBytes = PdfSigner.Sign(
            currentPdfBytes, 
            user1Pfx, 
            user1Password, 
            reason: "Reviewed by Accountant", 
            location: "Hanoi, Vietnam",
            x: 40, 
            y: 40, 
            width: 230, 
            height: 60);
        Console.WriteLine("    ✅ Signer 1 signature attached successfully!\n");

        // -------------------------------------------------------------
        // Step 2: Signer 2 (Director) generates keys & signs bottom-right
        // -------------------------------------------------------------
        string user2Password = "DirectorPass123!";
        var (user2Pfx, user2PublicKey) = PdfSigner.GenerateCertificate("Huynh Ba Quoc (Director)", user2Password);
        Console.WriteLine("[2] Signer 2 (Director): 'Huynh Ba Quoc (Director)'");
        Console.WriteLine($"    Signing at Bottom-Right Box (X: 320, Y: 40, Width: 230, Height: 60)...");

        currentPdfBytes = PdfSigner.Sign(
            currentPdfBytes, 
            user2Pfx, 
            user2Password, 
            reason: "Approved by Director", 
            location: "Ho Chi Minh City, Vietnam",
            x: 320, 
            y: 40, 
            width: 230, 
            height: 60);
        Console.WriteLine("    ✅ Signer 2 signature attached successfully!\n");

        // Save the resulting multi-signed PDF to disk
        File.WriteAllBytes(outputPdf, currentPdfBytes);
        Console.WriteLine($"🎉 Document with visible signatures saved to '{outputPdf}'\n");

        // -------------------------------------------------------------
        // Step 3: Server Verification
        // -------------------------------------------------------------
        Console.WriteLine("[3] Server verifies final signed PDF against Director's Database Public Key...");
        bool isValid = PdfSigner.Verify(currentPdfBytes, user2PublicKey);
        if (isValid == true)
        {
            Console.WriteLine("🎉 Server: Signature VALID & MATCHES Database record (CN=Huynh Ba Quoc (Director))!");
        }
        else
        {
            Console.WriteLine("❌ Server: Verification FAILED!");
        }
    }
}
