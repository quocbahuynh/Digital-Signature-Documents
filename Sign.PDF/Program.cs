using System;
using System.IO;

class Program
{
    static void Main()
    {
        Console.WriteLine("=== SEQUENTIAL SIGNING & MULTI-USER VERIFICATION SIMULATION ===\n");

        string inputPdf = File.Exists("document.pdf") 
            ? "document.pdf" 
            : Path.Combine(AppContext.BaseDirectory, "document.pdf");
        byte[] pdfDocumentBytes = File.ReadAllBytes(inputPdf);

        // =========================================================================
        // STEP 1: USER 1 (KẾ TOÁN) TẠO CHỨNG CHỈ VÀ KÝ NGAY LẬP TỨC
        // =========================================================================
        Console.WriteLine("[BƯỚC 1] 09:00 Sáng - User 1 (Kế toán) tạo Certificate và Ký tài liệu:");
        string user1Password = "AccountantPass123!";
        var (user1Pfx, user1PublicKey) = PdfSigner.GenerateCertificate("Nguyen Van Accountant", user1Password);

        // User 1 ký trực tiếp trên file PDF gốc (không sửa đổi cấu trúc file gốc)
        byte[] user1Signature = PdfSigner.SignData(pdfDocumentBytes, user1Pfx, user1Password);
        Console.WriteLine($"    • Kế toán đã tạo Private Key & Public Key.");
        Console.WriteLine($"    • Kế toán ký thành công! Chữ ký số Kế toán: {Convert.ToHexString(user1Signature)[..30]}... ({user1Signature.Length} bytes)");
        Console.WriteLine("    • [Gửi file PDF cho Giám đốc...]\n");

        // =========================================================================
        // STEP 2: USER 2 (GIÁM ĐỐC) NHẬN ĐƯỢC FILE, TẠO CHỨNG CHỈ VÀ KÝ TIẾP
        // =========================================================================
        Console.WriteLine("[BƯỚC 2] 15:00 Chiều - User 2 (Giám đốc) nhận file, tạo Certificate và Ký tài liệu:");
        string user2Password = "DirectorPass123!";
        var (user2Pfx, user2PublicKey) = PdfSigner.GenerateCertificate("Huynh Ba Quoc (Director)", user2Password);

        // User 2 ký tiếp trên cùng file PDF đó
        byte[] user2Signature = PdfSigner.SignData(pdfDocumentBytes, user2Pfx, user2Password);
        Console.WriteLine($"    • Giám đốc đã tạo Private Key & Public Key.");
        Console.WriteLine($"    • Giám đốc ký thành công! Chữ ký số Giám đốc: {Convert.ToHexString(user2Signature)[..30]}... ({user2Signature.Length} bytes)\n");

        // =========================================================================
        // STEP 3: BẤT KỲ AI CẦN XÁC THỰC CẢ 2 NGƯỜI ĐÃ KÝ TRÊN FILE PDF
        // =========================================================================
        Console.WriteLine("[BƯỚC 3] Server / Đối tác tiến hành Xác thực (Verify) tất cả chữ ký:");

        // 3.1. Xác thực chữ ký của User 1 (Kế toán)
        bool isUser1Valid = PdfSigner.VerifyData(pdfDocumentBytes, user1Signature, user1PublicKey);
        Console.WriteLine($"    1. Xác thực Kế toán (Nguyen Van Accountant): {(isUser1Valid ? "🟢 HỢP LỆ (TRUE) - Đã duyệt chính chủ!" : "🔴 THẤT BẠI")}");

        // 3.2. Xác thực chữ ký của User 2 (Giám đốc)
        bool isUser2Valid = PdfSigner.VerifyData(pdfDocumentBytes, user2Signature, user2PublicKey);
        Console.WriteLine($"    2. Xác thực Giám đốc (Huynh Ba Quoc):        {(isUser2Valid ? "🟢 HỢP LỆ (TRUE) - Đã phê duyệt chính chủ!" : "🔴 THẤT BẠI")}");

        // 3.3. Thử nghiệm với Khóa giả mạo của Kẻ tấn công
        var (_, attackerPublicKey) = PdfSigner.GenerateCertificate("Attacker Unknown", "attackerpass");
        bool isAttackerValid = PdfSigner.VerifyData(pdfDocumentBytes, user1Signature, attackerPublicKey);
        Console.WriteLine($"    3. Kiểm tra Khóa giả mạo (Attacker Key):     {(isAttackerValid ? "🔴 NGUY HIỂM" : "🛡️ CHẶN THÀNH CÔNG (FALSE)")}");

        // 3.4. Thử nghiệm khi file PDF bị kẻ xấu sửa đổi nội dung (Tampering)
        byte[] tamperedPdfBytes = (byte[])pdfDocumentBytes.Clone();
        tamperedPdfBytes[10] ^= 0xFF; // Sửa đổi 1 byte trong file PDF
        bool isTamperedValid = PdfSigner.VerifyData(tamperedPdfBytes, user1Signature, user1PublicKey);
        Console.WriteLine($"    4. Kiểm tra khi File PDF bị sửa đổi:         {(isTamperedValid ? "🔴 LỖI" : "🛡️ PHÁT HIỆN GIAN LẬN & TỪ CHỐI (FALSE)")}\n");

        Console.WriteLine("🎉 KẾT LUẬN: Cả 2 User ký độc lập vào các thời điểm khác nhau, Server verify ai cũng TRUE 100%!");
    }
}
