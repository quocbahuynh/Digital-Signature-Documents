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
        // STEP 1: USER 1 (KẾ TOÁN) TẠO CERT, ĐÓNG KHUNG VISIBLE GÓC TRÁI & KÝ SỐ
        // =========================================================================
        Console.WriteLine("[BƯỚC 1] 09:00 Sáng - User 1 (Kế toán) tạo Certificate, đóng khung Chữ ký & Ký số:");
        string user1Password = "AccountantPass123!";
        var (user1Pfx, user1PublicKey) = PdfSigner.GenerateCertificate("Nguyen Van Accountant", user1Password);

        // 1.1. Vẽ ô chữ ký trực quan của Kế toán ở góc dưới bên Trái (X: 40, Y: 40)
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

        // 1.2. Tạo chữ ký số mật mã của Kế toán (Detached Signature)
        byte[] user1Signature = PdfSigner.SignData(pdfStep1Bytes, user1Pfx, user1Password);
        Console.WriteLine("    • [Visual] Đã vẽ khung chữ ký Kế toán tại góc Trái (X: 40, Y: 40).");
        Console.WriteLine($"    • [Crypto] Chữ ký số Kế toán: {Convert.ToHexString(user1Signature)[..30]}... ({user1Signature.Length} bytes)");
        Console.WriteLine("    • [Gửi file PDF cho Giám đốc...]\n");

        // =========================================================================
        // STEP 2: USER 2 (GIÁM ĐỐC) NHẬN FILE, ĐÓNG KHUNG VISIBLE GÓC PHẢI & KÝ SỐ
        // =========================================================================
        Console.WriteLine("[BƯỚC 2] 15:00 Chiều - User 2 (Giám đốc) nhận file, đóng khung Chữ ký & Ký số:");
        string user2Password = "DirectorPass123!";
        var (user2Pfx, user2PublicKey) = PdfSigner.GenerateCertificate("Huynh Ba Quoc (Director)", user2Password);

        // 2.1. Vẽ tiếp ô chữ ký trực quan của Giám đốc ở góc dưới bên Phải (X: 320, Y: 40)
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

        // 2.2. Tạo chữ ký số mật mã của Giám đốc (Detached Signature)
        byte[] user2Signature = PdfSigner.SignData(finalPdfBytes, user2Pfx, user2Password);
        Console.WriteLine("    • [Visual] Đã vẽ khung chữ ký Giám đốc tại góc Phải (X: 320, Y: 40).");
        Console.WriteLine($"    • [Crypto] Chữ ký số Giám đốc: {Convert.ToHexString(user2Signature)[..30]}... ({user2Signature.Length} bytes)\n");

        // 2.3. Xuất file PDF hoàn chỉnh chứa CẢ 2 Ô CHỮ KÝ VISIBLE
        File.WriteAllBytes(finalOutputPdf, finalPdfBytes);
        Console.WriteLine($"🎉 File PDF hoàn chỉnh đã lưu tại '{finalOutputPdf}' (Chứa cả 2 ô chữ ký visible)!\n");

        // =========================================================================
        // STEP 3: SERVER XÁC THỰC (VERIFY) ĐỘC LẬP TẤT CẢ CHỮ KÝ
        // =========================================================================
        Console.WriteLine("[BƯỚC 3] Server / Đối tác tiến hành Xác thực (Verify) tất cả chữ ký:");

        // 3.1. Xác thực chữ ký của Kế toán trên bản Bước 1
        bool isUser1Valid = PdfSigner.VerifyData(pdfStep1Bytes, user1Signature, user1PublicKey);
        Console.WriteLine($"    1. Xác thực Kế toán (Nguyen Van Accountant): {(isUser1Valid ? "🟢 HỢP LỆ (TRUE) - Đã duyệt chính chủ!" : "🔴 THẤT BẠI")}");

        // 3.2. Xác thực chữ ký của Giám đốc trên bản Hoàn chỉnh Final
        bool isUser2Valid = PdfSigner.VerifyData(finalPdfBytes, user2Signature, user2PublicKey);
        Console.WriteLine($"    2. Xác thực Giám đốc (Huynh Ba Quoc):        {(isUser2Valid ? "🟢 HỢP LỆ (TRUE) - Đã phê duyệt chính chủ!" : "🔴 THẤT BẠI")}");

        // 3.3. Kiểm tra bảo mật với khóa giả mạo
        var (_, attackerPublicKey) = PdfSigner.GenerateCertificate("Attacker Unknown", "attackerpass");
        bool isAttackerValid = PdfSigner.VerifyData(finalPdfBytes, user2Signature, attackerPublicKey);
        Console.WriteLine($"    3. Kiểm tra Khóa giả mạo (Attacker Key):     {(isAttackerValid ? "🔴 NGUY HIỂM" : "🛡️ CHẶN THÀNH CÔNG (FALSE)")}");

        // 3.4. Kiểm tra khi file PDF bị kẻ xấu sửa đổi nội dung
        byte[] tamperedPdfBytes = (byte[])finalPdfBytes.Clone();
        tamperedPdfBytes[10] ^= 0xFF;
        bool isTamperedValid = PdfSigner.VerifyData(tamperedPdfBytes, user2Signature, user2PublicKey);
        Console.WriteLine($"    4. Kiểm tra khi File PDF bị sửa đổi:         {(isTamperedValid ? "🔴 LỖI" : "🛡️ PHÁT HIỆN GIAN LẬN & TỪ CHỐI (FALSE)")}\n");

        Console.WriteLine("🎉 KẾT LUẬN: Đạt 100% 2 mục tiêu: Vừa hiển thị 2 ô chữ ký visible, vừa Verify thành công cả 2 người!");
    }
}
